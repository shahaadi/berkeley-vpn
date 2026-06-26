// Capture a GlobalProtect gateway prelogin-cookie for vpn.berkeley.edu using the
// system WebKit engine (the same engine as Safari) — no Chrome.
//
// A WKWebView window shows the CalNet + Duo login. Once the CalNet SSO session is
// established, URLSession (carrying the WebKit cookies and spoofing the
// "PAN GlobalProtect" User-Agent, which the server requires before it will hand
// out the token) replays the GlobalProtect SAML flow and reads the
// prelogin-cookie / saml-username from the gateway SAML ACS response headers.
//
// On success prints a JSON object with keys "prelogin-cookie" and "saml-username"
// (sorted, slashes unescaped) to stdout; progress and errors go to stderr.
// The --probe / --selftest diagnostic modes print their results to stdout (with
// failure detail on stderr).
//
// The WebKit data store is persistent, so after the first login the SSO session
// is reused and no Duo prompt appears until it expires.

import Cocoa
import WebKit

// MARK: - Configuration

let env = ProcessInfo.processInfo.environment
// Trim incidental whitespace (copy-paste / here-doc), fall back to the default if
// that leaves nothing, then normalise case once so every comparison matches.
let gatewayRaw = (env["GP_GATEWAY"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
let gateway = (gatewayRaw.isEmpty ? "campus-split.vpn.berkeley.edu" : gatewayRaw).lowercased()
// The server only returns the token for this exact User-Agent; with a browser UA
// it serves a "download the app" page instead. Used on every hop (stock
// Shibboleth doesn't bind sessions to the UA, so the IdP GET tolerates it).
let gpUserAgent = "PAN GlobalProtect"
// Spoofed GP client identity. clientVer=4100 mimics a recent GlobalProtect
// client (some gateways gate behaviour on it); clientos=Mac selects the Mac flow.
let gpClientQuery = "tmp=tmp&clientVer=4100&clientos=Mac"
let preloginURLString = "https://\(gateway)/ssl-vpn/prelogin.esp?\(gpClientQuery)"
// Per-request network timeouts for the capture/probe sessions.
let requestTimeout: Double = 20
let resourceTimeout: Double = 30
// Seconds to wait for the interactive login, clamped to a sane finite range. Any
// adjustment / bad value is reported when the login window opens (not in
// --probe/--selftest), so offline modes stay quiet.
let defaultLoginTimeout = 240.0
let minLoginTimeout = 10.0
let maxLoginTimeout = 3600.0
let (loginTimeout, loginTimeoutWarning): (Double, String?) = {
    guard let raw = env["GP_TIMEOUT"]?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return (defaultLoginTimeout, nil) }
    guard let v = Double(raw), v.isFinite else {
        return (defaultLoginTimeout, "GP_TIMEOUT '\(raw)' is not a usable number; using \(Int(defaultLoginTimeout))s")
    }
    let clamped = min(max(minLoginTimeout, v), maxLoginTimeout)
    let effective = clamped.rounded(.down)   // whole seconds: display == actual deadline
    // Report ANY adjustment — clamping out-of-range OR flooring a fractional value.
    let warning = effective != v ? "GP_TIMEOUT '\(raw)' adjusted to \(Int(effective))s" : nil
    return (effective, warning)
}()
// Watchdog for the post-login capture phase: the login timer is neutralised by
// the `done` guard once login completes, and getAllCookies has no timeout itself.
let captureTimeout: Double = 120
let maxRedirects = 10   // total redirect hops allowed across the capture flow
let windowWidth: CGFloat = 520
let windowHeight: CGFloat = 680
let logSnippetChars = 200   // shib body shown on a parse failure
let urlDisplayChars = 64    // IdP URL shown by --probe / off-site failures
// Max distance from '&' to ';' to treat as an entity (body is at most
// maxEntitySpan-1 chars); the longest real body is 8 ("#x10FFFF" / "#1114111").
let maxEntitySpan = 12
// The five XML predefined entities, lowercase as stock Shibboleth emits them;
// uppercase HTML variants (&AMP;) are intentionally not handled.
let htmlNamedEntities: [String: Character] = ["amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'"]

// Form-field patterns (stock Shibboleth post-binding: a SINGLE form, double-quoted
// attributes, name before value). Each pattern is matched independently over the
// whole page, so the single-form assumption is what ties the action URL to the
// SAMLResponse/RelayState fields. Whitespace-anchored before each attribute so a
// `data-action`/`data-name` style attribute can't be mis-captured. Shared by the
// capture and the offline self-test so they can't drift.
let actionPattern = "<form[^>]*\\saction=\"([^\"]+)\""
let samlResponsePattern = "\\sname=\"SAMLResponse\"[^>]*\\svalue=\"([^\"]+)\""
let relayStatePattern = "\\sname=\"RelayState\"[^>]*\\svalue=\"([^\"]*)\""
// The prelogin XML wrapper around the base64 SAML AuthnRequest.
let samlRequestPattern = "<saml-request>(.*?)</saml-request>"
// Shared matching options, and the patterns compiled once at startup into an
// immutable dictionary. NSRegularExpression matching is thread-safe and the
// dictionary never mutates, so the capture (delegate + global queues) and the
// self-test reuse the same compiled objects without locks or per-call rebuilds.
let regexOptions: NSRegularExpression.Options = [.caseInsensitive, .dotMatchesLineSeparators]
let compiledPatterns: [String: NSRegularExpression] = {
    var d: [String: NSRegularExpression] = [:]
    for p in [actionPattern, samlResponsePattern, relayStatePattern, samlRequestPattern] {
        d[p] = try? NSRegularExpression(pattern: p, options: regexOptions)
    }
    return d
}()

func errlog(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }
func die(_ s: String) -> Never { errlog(s); exit(1) }
func truncated(_ s: String, _ n: Int) -> String { s.count > n ? String(s.prefix(n)) + "…" : s }

/// Decode a numeric character reference, refusing control characters (C0, DEL,
/// C1) — belt-and-suspenders sanitisation of decoded SAML form values — and
/// anything that isn't a valid scalar (surrogates / out-of-range).
func scalarChar(_ code: UInt32) -> Character? {
    guard code >= 0x20, code != 0x7F, !(0x80...0x9F).contains(code),
          let u = Unicode.Scalar(code) else { return nil }
    return Character(u)
}

// A bounded session for the prelogin fetches that don't need the SSO cookies
// (launch + --probe), so they can't hang on a stalled link. Built on demand so
// --selftest doesn't allocate one. It uses the default redirect policy (no per-hop
// host check, unlike the capture session) — safe because it carries no cookies and
// its result, the saml-request URL, is re-validated as https + .berkeley.edu.
// Has no delegate, so it needs no finishTasksAndInvalidate(): once fetchSamlURL
// returns (its single task already finished), the last reference drops and the
// session deallocates — no retain cycle, unlike the capture session.
func makeDirectSession() -> URLSession {
    let cfg = URLSessionConfiguration.ephemeral
    cfg.timeoutIntervalForRequest = requestTimeout
    cfg.timeoutIntervalForResource = resourceTimeout
    return URLSession(configuration: cfg)
}

// MARK: - HTML entity decoding (Shibboleth hex-encodes form attribute values)

/// Decode HTML entities in a single left-to-right pass, so a produced '&' is
/// never re-scanned. This avoids double-decoding, e.g. "&#x26;lt;" and "&amp;lt;"
/// both correctly yield the literal "&lt;", not "<". Handles the five XML
/// predefined named entities and numeric (decimal/hex) character references;
/// any other named entity, or a control/surrogate/out-of-range code point, is
/// left as-is (sufficient for SAML attribute values). The scan window is bounded
/// to maxEntitySpan, keeping it O(n).
func htmlUnescape(_ s: String) -> String {
    guard s.contains("&") else { return s }
    let chars = Array(s)
    var out = ""
    out.reserveCapacity(chars.count)
    var i = 0
    while i < chars.count {
        if chars[i] == "&" {
            let scanEnd = min(i + 1 + maxEntitySpan, chars.count)
            if i + 1 < scanEnd, let semi = chars[(i + 1)..<scanEnd].firstIndex(of: ";") {
                let body = String(chars[(i + 1)..<semi])
                var decoded: Character?
                if body.hasPrefix("#x") || body.hasPrefix("#X") {
                    if let code = UInt32(body.dropFirst(2), radix: 16) { decoded = scalarChar(code) }
                } else if body.hasPrefix("#") {
                    if let code = UInt32(body.dropFirst(1), radix: 10) { decoded = scalarChar(code) }
                } else {
                    decoded = htmlNamedEntities[body]
                }
                if let d = decoded { out.append(d); i = semi + 1; continue }
            }
        }
        out.append(chars[i]); i += 1
    }
    return out
}

// MARK: - Regex helper

func firstMatch(_ pattern: String, in text: String) -> String? {
    // Prefer the precompiled object; fall back to compiling on the fly for any
    // ad-hoc pattern (and in the impossible event a constant one failed to build).
    guard let re = compiledPatterns[pattern]
            ?? (try? NSRegularExpression(pattern: pattern, options: regexOptions))
    else { return nil }
    let range = NSRange(text.startIndex..., in: text)
    guard let m = re.firstMatch(in: text, options: [], range: range), m.numberOfRanges > 1,
          let r = Range(m.range(at: 1), in: text) else { return nil }
    return String(text[r])
}

/// Percent-encode a value for an application/x-www-form-urlencoded body: every
/// non-unreserved character becomes %XX, and a space becomes '+' (the form
/// encoding's special case). A literal '+' is percent-encoded to %2B first, so
/// the two can never be confused on decode. (Real SAML values carry no spaces;
/// this stays spec-correct regardless and is exercised by the self-test.)
func formEncode(_ s: String) -> String {
    // RFC 3986 unreserved set, ASCII only (CharacterSet.alphanumerics is
    // Unicode-wide and would pass non-ASCII letters/digits through unencoded).
    let unreserved = CharacterSet(charactersIn:
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    let pct = s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s
    return pct.replacingOccurrences(of: "%20", with: "+")
}

/// POST the gateway prelogin and return the decoded shib SAML IdP URL.
/// Shared by the login window, the capture, and --probe. Logs its own failure cause.
func fetchSamlURL(using session: URLSession = makeDirectSession()) -> URL? {
    guard let pre = URL(string: preloginURLString) else {
        errlog("prelogin failed: could not build URL for gateway '\(gateway)'"); return nil
    }
    var req = URLRequest(url: pre); req.httpMethod = "POST"
    req.setValue(gpUserAgent, forHTTPHeaderField: "User-Agent")
    let sem = DispatchSemaphore(value: 0)
    var result: URL?
    var failure: String?
    session.dataTask(with: req) { data, resp, err in
        defer { sem.signal() }
        if let err = err { failure = err.localizedDescription; return }
        let status = (resp as? HTTPURLResponse).map { " (HTTP \($0.statusCode))" } ?? ""
        guard let data = data, let s = String(data: data, encoding: .utf8) else {
            failure = "empty/undecodable prelogin response" + status; return
        }
        guard let b64 = firstMatch(samlRequestPattern, in: s),
              let dd = Data(base64Encoded: b64, options: .ignoreUnknownCharacters),
              let us = String(data: dd, encoding: .utf8), let u = URL(string: us) else {
            failure = "no usable <saml-request> in prelogin response" + status; return
        }
        guard u.scheme == "https", let host = u.host?.lowercased(), host.hasSuffix(".berkeley.edu") else {
            failure = "saml-request points off-site: \(truncated(u.absoluteString, urlDisplayChars))"; return
        }
        result = u
    }.resume()
    sem.wait()
    if result == nil, let f = failure { errlog("prelogin failed: \(f)") }
    return result
}

// MARK: - URLSession capture (runs after SSO is established in the WebView)

final class Capturer: NSObject, URLSessionTaskDelegate {
    // preloginCookie/samlUsername are written on both the delegate queue (redirect
    // scan) and the global queue (run's final scan); redirectCount only on the
    // delegate queue. Safe because send() blocks run() on a semaphore for the whole
    // task, so the signal/wait pair orders every write before run() reads.
    var preloginCookie: String?
    var samlUsername: String?
    var redirectCount = 0
    let cookies: [HTTPCookie]
    lazy var session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpShouldSetCookies = true
        cfg.httpCookieAcceptPolicy = .always
        // Hard-cap each request so the capture phase can't hang on a stalled link.
        cfg.timeoutIntervalForRequest = requestTimeout
        cfg.timeoutIntervalForResource = resourceTimeout
        // Inject the WebKit SSO cookies into the config's OWN cookie storage (a
        // bare HTTPCookieStorage() is non-functional). Only Berkeley cookies are
        // needed here, so filter for least privilege (URLSession would scope them
        // by domain at send time anyway).
        for c in self.cookies {
            let d = c.domain.lowercased()
            if d == "berkeley.edu" || d.hasSuffix(".berkeley.edu") {
                cfg.httpCookieStorage?.setCookie(c)
            }
        }
        return URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }()
    init(cookies: [HTTPCookie]) {
        self.cookies = cookies
        super.init()
    }

    func scan(_ resp: HTTPURLResponse) {
        // Treat a present-but-empty header as absent — an empty token is not usable.
        if let c = resp.value(forHTTPHeaderField: "prelogin-cookie"), !c.isEmpty { preloginCookie = c }
        if let u = resp.value(forHTTPHeaderField: "saml-username"), !u.isEmpty { samlUsername = u }
    }

    // Inspect redirect responses too — the token can ride on a 302.
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        scan(response)
        // Stop once we have BOTH fields we need (they ride the same ACS response);
        // the one-time cookie is already scanned, so cancelling here means a
        // followed redirect can't consume it first. Cancelling completes the task
        // normally with this 3xx as its response (verified: err == nil).
        if preloginCookie != nil && samlUsername != nil { completionHandler(nil); return }
        // Defense-in-depth: only follow https redirects within Berkeley, and cap
        // the total hop count across the capture flow. (The real flow only bounces
        // among *.berkeley.edu hosts, far under the cap.)
        redirectCount += 1
        guard redirectCount <= maxRedirects, let u = request.url, u.scheme == "https",
              (u.host?.lowercased().hasSuffix(".berkeley.edu") ?? false) else {
            errlog("  refusing redirect to \(request.url.map { truncated($0.absoluteString, urlDisplayChars) } ?? "?")")
            completionHandler(nil); return
        }
        var req = request
        req.setValue(gpUserAgent, forHTTPHeaderField: "User-Agent")
        completionHandler(req)
    }

    /// Perform one request (GET or POST). Returns nil and logs the cause on error.
    func send(_ url: URL, method: String = "GET", body: Data? = nil,
              contentType: String? = nil) -> (Data, HTTPURLResponse)? {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(gpUserAgent, forHTTPHeaderField: "User-Agent")
        if let ct = contentType { req.setValue(ct, forHTTPHeaderField: "Content-Type") }
        req.httpBody = body
        let sem = DispatchSemaphore(value: 0)
        var out: (Data, HTTPURLResponse)?
        var failure: String?
        session.dataTask(with: req) { data, resp, err in
            if let err = err { failure = err.localizedDescription }
            // A delivered response intentionally takes precedence over `err`: a
            // cancelled redirect arrives as (empty data, 3xx response, err=nil),
            // which is our success path, not a failure.
            if let d = data, let r = resp as? HTTPURLResponse { out = (d, r) }
            sem.signal()
        }.resume()
        sem.wait()
        if out == nil { errlog("  \(method) \(url.host ?? "?") failed: \(failure ?? "no response")") }
        return out
    }

    /// Full GP SAML dance; returns true once both cookie and username are captured.
    func run() -> Bool {
        // 1. Fresh prelogin -> shib SAML request URL (over this session so the SSO
        //    cookies and GP User-Agent are carried through).
        guard let samlURL = fetchSamlURL(using: session) else { return false }
        // 2. GET the shib SAML URL (SSO active -> auto-post form, no Duo).
        guard let (hd, shibResp) = send(samlURL) else { return false }
        let html = String(data: hd, encoding: .utf8) ?? ""
        guard let action = firstMatch(actionPattern, in: html),
              let samlResp = firstMatch(samlResponsePattern, in: html),
              let actionURL = URL(string: htmlUnescape(action)),
              actionURL.scheme == "https", actionURL.host?.lowercased() == gateway else {
            errlog("could not parse SAML form from shib response (HTTP \(shibResp.statusCode); SSO cookie not carried?)")
            let snippet = html.replacingOccurrences(of: "\n", with: " ")
            errlog("  shib returned: \(truncated(snippet, logSnippetChars))")
            return false
        }
        // 3. POST SAMLResponse (+ RelayState if the form carried one — a
        //    present-but-empty value is included, matching browser form submission).
        var bodyStr = "SAMLResponse=\(formEncode(htmlUnescape(samlResp)))"
        if let relay = firstMatch(relayStatePattern, in: html) {
            bodyStr += "&RelayState=\(formEncode(htmlUnescape(relay)))"
        }
        guard let (_, acsResp) = send(actionURL, method: "POST", body: Data(bodyStr.utf8),
                                      contentType: "application/x-www-form-urlencoded") else {
            return false
        }
        scan(acsResp)
        if preloginCookie == nil || samlUsername == nil {
            let missing = [("prelogin-cookie", preloginCookie), ("saml-username", samlUsername)]
                .filter { $0.1 == nil }.map { $0.0 }.joined(separator: ", ")
            errlog("ACS response missing \(missing) (HTTP \(acsResp.statusCode))")
        }
        return preloginCookie != nil && samlUsername != nil
    }
}

// MARK: - WebKit login window

final class App: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    var done = false
    var captured = false

    func applicationDidFinishLaunching(_ note: Notification) {
        if let w = loginTimeoutWarning { errlog("note: \(w)") }
        let cfg = WKWebViewConfiguration()
        // Note on autofill/passkeys: neither works in this window, by design of the
        // platform. macOS WKWebView has no web-form password AutoFill surface (that
        // path is iOS-only), and passkeys/WebAuthn require an associated-domains
        // entitlement that only berkeley.edu/duosecurity.com could grant. An
        // ASWebAuthenticationSession would unlock both, but it sandboxes its cookies
        // and this tool must read the SSO cookie jar to replay the SAML flow. So you
        // type your CalNet password and approve Duo by push/passcode; the persistent
        // data store below means re-login is rare.
        cfg.websiteDataStore = .default()   // persistent -> reuse SSO next time
        webView = WKWebView(frame: NSRect(x: 0, y: 0, width: windowWidth, height: windowHeight),
                            configuration: cfg)
        webView.navigationDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: windowWidth, height: windowHeight),
                          styleMask: [.titled, .closable, .miniaturizable],
                          backing: .buffered, defer: false)
        window.title = "Berkeley VPN — CalNet login"
        window.contentView = webView
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        // Fetch the start URL off-main so a slow/unreachable network can't freeze
        // the window before it appears.
        DispatchQueue.global().async {
            guard let start = fetchSamlURL() else {
                DispatchQueue.main.async { die("ERROR: could not reach \(gateway) prelogin") }
                return
            }
            DispatchQueue.main.async { self.webView.load(URLRequest(url: start)) }
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + loginTimeout) {
            if !self.done { die("ERROR: timed out waiting for login (\(Int(loginTimeout))s)") }
        }
    }

    // If the user closes the window before login, exit promptly. Once capture is
    // in flight, let its own exit()/die() end the process.
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool {
        if !done { die("ERROR: login window closed before completing") }
        return false
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard !done, let host = webView.url?.host?.lowercased() else { return }
        // The SAML flow lands on the gateway host (always *.vpn.berkeley.edu, but
        // also match the configured gateway so a custom GP_GATEWAY still works);
        // landing there means the CalNet SSO completed.
        guard host == gateway || host == "vpn.berkeley.edu"
              || host.hasSuffix(".vpn.berkeley.edu") else { return }
        done = true
        errlog("Login detected — capturing token…")
        window.orderOut(nil)   // hide the finished login window during capture

        // Bound the capture phase (getAllCookies has no timeout, and the login
        // watchdog is neutralised once done == true). Guarded by `captured` so a
        // just-finished capture can't print a spurious timeout.
        DispatchQueue.main.asyncAfter(deadline: .now() + captureTimeout) {
            if !self.captured { die("ERROR: token capture timed out (\(Int(captureTimeout))s)") }
        }

        let store = webView.configuration.websiteDataStore.httpCookieStore
        store.getAllCookies { cookies in
            DispatchQueue.global().async {
                let cap = Capturer(cookies: cookies)
                _ = cap.run()
                cap.session.finishTasksAndInvalidate()   // break the delegate retain cycle
                guard let pc = cap.preloginCookie, let user = cap.samlUsername else {
                    die("ERROR: token capture failed (see messages above)")
                }
                let enc = JSONEncoder()
                // Cookies/usernames may contain '/', which the default encoder
                // escapes to '\/' and corrupts downstream; sorted keys make the
                // output deterministic.
                enc.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
                guard let data = try? enc.encode(["prelogin-cookie": pc, "saml-username": user]) else {
                    die("ERROR: failed to encode token JSON")
                }
                // Set `captured` and write/exit on main, the same queue as the
                // capture watchdog, so the two can't race.
                DispatchQueue.main.async {
                    self.captured = true
                    FileHandle.standardOutput.write(data + Data("\n".utf8))
                    exit(0)
                }
            }
        }
    }
}

// MARK: - Verification modes (--selftest is offline; --probe makes one live request)

func probe() -> Never {
    guard let url = fetchSamlURL() else {
        die("FAIL  could not reach \(gateway) prelogin or parse its saml-request")
    }
    print("OK  \(gateway) prelogin reachable over TLS")
    print("OK  SAML IdP: \(truncated(url.absoluteString, urlDisplayChars))")
    exit(0)
}

func selftest() -> Never {
    // A fixed host keeps this offline check independent of GP_GATEWAY.
    let host = "vpn.example.edu"
    // base64 containing the chars Shibboleth hex-encodes in attributes (+ / =)
    let rawSAML = "PHNhbWxwOlJlc3BvbnNlPnRlc3QrL3Rlc3Q9PC9zYW1scDpSZXNwb25zZT4="
    let encSAML = rawSAML.replacingOccurrences(of: "+", with: "&#x2b;")
                         .replacingOccurrences(of: "/", with: "&#x2f;")
                         .replacingOccurrences(of: "=", with: "&#x3d;")
    let html = """
    <html><body onload="document.forms[0].submit()">
    <form action="https&#x3a;&#x2f;&#x2f;\(host)&#x2f;SAML20&#x2f;SP&#x2f;ACS" method="post">
    <input type="hidden" name="RelayState" value="ss&#x3a;mem&#x3a;abc&amp;def"/>
    <input type="hidden" name="SAMLResponse" value="\(encSAML)"/>
    </form></body></html>
    """
    let noRelayHTML = "<form action=\"x\"><input name=\"SAMLResponse\" value=\"abc\"/></form>"
    // Attributes separated by newlines (still valid HTML; the anchored regex must match).
    let nlForm = "<form\n action=\"https://h/acs\"\n method=\"post\">\n<input\n name=\"SAMLResponse\"\n value=\"abc\"/>"
    var pass = true
    func check(_ label: String, _ got: String?, _ want: String?) {
        if got == want { print("OK  \(label)") }
        else { errlog("FAIL \(label): got \(String(describing: got)) want \(String(describing: want))"); pass = false }
    }
    check("action URL", firstMatch(actionPattern, in: html).map(htmlUnescape), "https://\(host)/SAML20/SP/ACS")
    check("SAMLResponse decode", firstMatch(samlResponsePattern, in: html).map(htmlUnescape), rawSAML)
    check("RelayState decode", firstMatch(relayStatePattern, in: html).map(htmlUnescape), "ss:mem:abc&def")
    check("entity decode (dec/hex/named)", htmlUnescape("a&#43;b&#x2f;c&#X2B;d&amp;e&lt;f"), "a+b/c+d&e<f")
    check("named amp not double-decoded", htmlUnescape("&amp;lt;"), "&lt;")
    check("numeric amp not double-decoded", htmlUnescape("&#x26;lt;"), "&lt;")
    check("surrogate left literal", htmlUnescape("&#xD800;"), "&#xD800;")
    check("out-of-range left literal", htmlUnescape("&#x110000;"), "&#x110000;")
    check("C0 control not decoded", htmlUnescape("&#0;a&#9;"), "&#0;a&#9;")
    check("DEL/C1 control not decoded", htmlUnescape("&#127;&#x80;"), "&#127;&#x80;")
    check("bare/dangling amp untouched", htmlUnescape("a & b&"), "a & b&")
    check("empty SAMLResponse rejected",
          firstMatch(samlResponsePattern, in: "<input name=\"SAMLResponse\" value=\"\"/>"), nil)
    check("absent RelayState omitted", firstMatch(relayStatePattern, in: noRelayHTML), nil)
    check("present-empty RelayState included",
          firstMatch(relayStatePattern, in: "<input name=\"RelayState\" value=\"\"/>"), "")
    check("newline-separated form parses", firstMatch(actionPattern, in: nlForm), "https://h/acs")
    check("formEncode space -> +", formEncode("a b c"), "a+b+c")
    check("formEncode reserved +/= percent-encoded", formEncode("a+b/c=d"), "a%2Bb%2Fc%3Dd")
    check("formEncode unreserved passthrough", formEncode("Xy9-._~"), "Xy9-._~")
    // Exercise firstMatch's on-the-fly fallback (a pattern not in compiledPatterns).
    check("firstMatch ad-hoc pattern (fallback)", firstMatch("z(.)z", in: "zXz"), "X")
    print(pass ? "SELFTEST PASS" : "SELFTEST FAIL")
    exit(pass ? 0 : 1)
}

func usageText() -> String {
    """
    Usage: swift capture.swift [-h | --help | --probe | --selftest]
      (no args)    open the WebKit CalNet+Duo login and print the captured token JSON
      --probe      one live prelogin request to the gateway (no login)
      --selftest   offline parser self-checks
      -h, --help   show this help
    Env: GP_GATEWAY=<host> (current: \(gateway)), GP_TIMEOUT=<seconds> (current: \(Int(loginTimeout)))
    """
}

// MARK: - Entry

let cliArgs = Array(CommandLine.arguments.dropFirst())
let knownFlags: Set<String> = ["-h", "--help", "--probe", "--selftest"]
// Help wins over everything (matches connect.sh), then reject unknown args.
if cliArgs.contains("-h") || cliArgs.contains("--help") { print(usageText()); exit(0) }
let unknownArgs = cliArgs.filter { !knownFlags.contains($0) }
if !unknownArgs.isEmpty {
    errlog("unknown argument(s): \(unknownArgs.joined(separator: " "))"); errlog(usageText()); exit(2)
}
let modeFlags = cliArgs.filter { $0 == "--probe" || $0 == "--selftest" }
// Reject only a genuine conflict (two DIFFERENT modes); a harmless repeat of the
// same flag (e.g. `--probe --probe`) is idempotent and allowed.
if Set(modeFlags).count > 1 {
    errlog("use at most one mode flag (--probe or --selftest)"); errlog(usageText()); exit(2)
}
if modeFlags.contains("--selftest") { selftest() }   // offline; no gateway needed

// Validate the gateway before building any URL from it: a strict hostname charset
// both stops the URL(string:) templates from trapping and prevents a typo'd or
// hostile value (e.g. "host@evil.tld") from redirecting requests. (No port form.)
// Require a dotted hostname of well-formed labels (blocks `@`/`:`/`/` injection
// and degenerate forms like leading/trailing dots or `a..b`).
guard gateway.range(of: "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$",
                    options: .regularExpression) != nil,
      URL(string: preloginURLString) != nil else {
    die("ERROR: invalid GP_GATEWAY: '\(gateway)'")
}

if modeFlags.contains("--probe") { probe() }

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
