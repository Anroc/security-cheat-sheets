# OAuth 2.0 - Cheat Sheet

OAuth is a protocol to authorize clients (usually applications) to access resources stored on resource server (usually OAuth provider). In the earlier days, this problem was solved by requesting the password for a 3rd party resource server directly from the resource owner (user). Using OAuth, this "pass-the-password" problem is solved, since users don't enter their password directly into the requesting site but authenticate to the resource server and then grant access to other clients. 

There are different security pitfalls when implementing the OAuth flow. The following guidelines are divided into recommendations for clients (Applications that want to get access to a resource) and resource server (The OAuth provider).

**General Resources:**

* https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15 - Different attacks on OAuth 2.0
* https://oauth.net/2/ - Explaination of OAuth 2.0
* https://owasp.org/www-pdf-archive/20151215-Top_X_OAuth_2_Hacks-asanso.pdf - Presentation on common OAuth attacks.


## Resource Server

The resource server is the service that holds the data of a user. It controls which service has access to which resource. It is responsible for revoking and granting access, based on the user's (resource owner) consent. 

### Prevent resuse of authorization code


In RFC 6749 - Section-4.1.3 [1] it states that: 

> The client MUST NOT use the authorization code  more than once.  If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code. 

If a resource owner would allow the reusability of the authorization code, it could lead to an account take over. 

Imagen Alice wants to visit "cute-cat-pictures.com" on an airport terminal using Facebook's OAuth. She authorized cute-cat-pictures.com to access her Facebook profile. After she is finished she logs off but does not delete her browsing history. Bob uses the same computer to also browse cute-cat-pictures.com. He also goes through the OAuth flow with Facebook. If Facebook now allows the reuse of the authorization code, Bob will be able to reuse the authorization code from Alice's previous authorization code request (stored in the browser history) to retrieve Alice access token from Facebook. [2]

**Prevention:** 

* Don't allow the reuse of the authorization code
* If reuse is attempted invalidate the issued token

**Resources:**

* [1] https://tools.ietf.org/html/rfc6749#section-4.1.3
* [2] www.ietf.org/mail-archive/web/oauth/current/msg09490.html

### Validate the redirect_uri

When registering a new OAuth application to the resource provider, you are asked to enter a redirect URI. This URI defines and fixes the endpoint where clients are redirected after failed or successful authorization. [1]

The *redirect_uri* should be passed on authorization request and code exchange and should be **validated for consistency** over these two requests as well as **validated against the initial redirect URI (schema)** specified when registering your application. 

If not validated properly, an attacker can hijack where the user is redirected to after authorization. This exposes the authorization code and eventually the access token of the user to the attacker. 

Possible attack scenarios:

* The *redirect_uri* is not validated at all. The attacker can craft a *redirect_uri* that points to a site under the attacker's control. Thus the authorization code can be captured. 
* The *redirect_uri* is only partially validated, but allows *path traversal*. [1] If combined with an *open redirect vulnerability* an attacker can carefully craft an authorization request which would redirect the user to an attacker site. This might also happen if the callback endpoint itself is vulnerable for *open redirect*. 
* The registered *redirect_uri* contains wildcards such as `https://*.exmaple.com/callback` to allow every subdomain of *example.com* to be a valid callback endpoint. However, if not validated properly the authorization service might interpret this as a regex wildcard an allow any character thus an attacker might craft `https://attacker.com/.example.com/callback` thus redirecting the victim to the attacker's site. [4]

An example that uses path traversal on the callback endpoint due to weak *redirect_uri* validation to redirect the user agent to an own gist, which will then load an external image to expose the authorization code in the query parameters. 
```
https://github.com/login/oauth/authorize?client_id=7e0a3cd836d3e544dbd9&redirect_uri=https%3A%2F%2Fgist.github.com%2Fauth%2Fgithub%2Fcallback/../../../homakov/8820324&response_type=code&scope=repo,gists,user,delete_repo,notifications
```
"How I hacked Github again" [2]

**Prevention:** 

* Validate *redirect_uri* carefully. If possible use equal checks to the initial specified URI. [3]
* Validate *redirect_uri* over multiple requests. The URI should not change. 
* Don't forward client to arbitrary *redirect_uri*

**Resources:**

* [1] https://tools.ietf.org/html/rfc6749#section-3.1.2
* [2] http://homakov.blogspot.com/2014/02/how-i-hacked-github-again.html
* [3] https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-2.1
* [4] https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-4.1.1


### Open Redirect Vulnerability

OAuth specifies that the user agent should be redirected to the passed redirect URL regardless of failed or successful authorization. This section was updated and now states:

> If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.

"4.1.2.1: Error Response" [1]

To prevent your OAuth server to become vulnerable to open redirects,  validate the *redirect_uri* first so that the client is **not** redirect to arbitrary resources. Resource Service should respond with a *400: Bad Request* instead.

**Prevention:** 

* On invalid requests will be answered with *400: Bad Request*
* Perform a redirect to an intermediate URI under the control of the authorization server to clear referrer information.
* Fragment "#" MUST be appended to the error redirect URI. This prevents the browser from reattaching the fragment from a previous URI to the new location URI. [2]

**Resources:**

* [1] https://tools.ietf.org/html/rfc6749#section-4.1.2.1
* [2] https://owasp.org/www-pdf-archive/20151215-Top_X_OAuth_2_Hacks-asanso.pdf

## Client

A client is an application that wants to gain access to a resource on a resource server. 

There are two kinds of clients:

* confidential clients (source code is inaccessible)
* public clients (source code is accessible, even in binary format)

Confidential clients can protect their *client_secret* and thus get stronger authentication guarantees from the authorization service since their identity can be verified. 

While the *client_secret* is important it is not as important as properly protecting the *redirect_uri*, since this is the point where secrets are exchanged. 

If the *client_secret* is leaked, the authenticity of the client can not be guaranteed any more. But since the *redirect_uri* still points to the correct client, confidentiality is not broken. 

### Native (Public) Clients

Native apps should not use the OAuth 2.0 *implicit flow*. In that flow, the access token is passed directly as a query parameter in the redirect URI. [1] 

> It is not recommended to use the implicit flow (and some servers prohibit this flow entirely) due to the inherent risks of returning access tokens in an HTTP redirect without any confirmation that it has been received by the client. 

"OAuth 2.0 Implicit Grant [2]"

That makes it inherently hard for the authorization service to bind the access token to a certain client since it simply doesn't know if it was received. Thus making replay attacks unpreventable. [3]

The implicit grant is especially vulnerable if combined with an open redirect vulnerability. Since the *access_code* is passed in a fragment (`#access_token=...`) and reattached on 303 redirects by the user agent, an attacker can steal the access token by crafting a redirect URI that links to another (open) redirect and finally ends up on the attacker's site. *For the full example and explanation see [5].*

Be aware that code grant does not prevent this kind of attack, but rather adds a condition: The attacker additionally needs to know the *client_secret* to successfully execute this attack and exchange the code for an access token. **Native apps are considered public clients and thus can not protect the *client_secret*.** Only with PKCE [4] this attack is mitigated.

Further, the access token might be stored in the browser's history. Thus allowing the attacker to retain the session of a previous user. [7]

**Prevention:**

* Public clients should use PCKE [2]
* Public clients should use authorization code grant [2]
* To protect the *client_secret* use *dynamic registration* [6] or don't issue a *client_secret* in the first place, thus preventing its leakage. 
* Use POST request to retrieve an access token to prevent leakage in browser history [7]

**Resources:**

* [1] https://tools.ietf.org/html/rfc6749#section-1.3.2
* [2] https://oauth.net/2/grant-types/implicit/
* [3] https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-4.1
* [4] https://oauth.net/2/pkce/
* [5] https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-4.1.2
* [6] https://tools.ietf.org/html/rfc7591
* [7] https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-4.3.2

### Cross-site request forgery (CSRF)

The callback endpoint is per default stateless. It doesn't know which user is currently following the redirect to the callback endpoint. Thus it will plainly execute the callback by extracting the code from the query parameter and requesting an access token using the code, client id, and client secret. 

This behavior can lead to CSRF (Cross-site request forgery) where an attacker tricks a victim in executing the callback for them. Thus binding the attackers OAuth resource to the victim's account. If the attacked service abuses OAuth for **authentication** instead for only authorization, it leads to an account take over, where the attacker can use the new attacked resource to authenticate as the victim. [1]

**Preventions:**

* Use PKCE. When using PKCE make sure that the authorization servicer supports it. [2]
* Pass a CSRF token in the state parameter. Don't forget to validate the token [2]


**Resources:**
* [1] http://homakov.blogspot.com/2012/07/saferweb-most-common-oauth2.html
* [2] https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-4.7.1


### Bearer token in URL

Bearer tokens should not be contained in the URL due to many reasons:

* The *access token* ends up being logged in *access.log* files [1]
* Copy and past issues [2]
* Risk of *access token* being leaked through the referrer header when linking from HTTP to HTTPS sites. [3]
* Caching of bearer token in the browser history [4]

**Prevention:**

* Don't use bearer token in URL. Rather send it in the *Authorization* header.

**Resources:**

* [1] https://thehackernews.com/2013/10/vulnerability-in-facebook-app-allows.html
* [2] https://owasp.org/www-pdf-archive/20151215-Top_X_OAuth_2_Hacks-asanso.pdf
* [3] http://intothesymmetry.blogspot.it/2015/10/on-oauth-token-hijacks-for-fun-and.html
* [4] https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-4.3.2


### The confused deputy - Access Token Injection

>  A confused deputy is a legitimate, more privileged computer program that is tricked by another program into misusing its authority on the system. It is a specific type of privilege escalation. 

"Wikipedia: Confused deputy problem" [1]

A "more privileged computer program" is usually the client who want to **authenticate** resource owner (users) based on OAuth. The confused deputy problem can happen if an evil app is authorized with the same user to the authorization service and then abuses the retrieved access token to authenticate to another client. 

If the client does not properly validate the access token (e.g. check that it is the intended recipient), it could lead to an account takeover. 

This problem can also be exploited in a CSRF fashion. An attacker could link additional authorization services to an authenticated client using CSRF. To prevent this, a client needs to validate the identity of the passed access token and the current user. [3] 

**Preventions:**

* Use authorization code grant, in that way an attacker can not craft a redirect URI since the request is initialized from the client. [2]
* Validate tokens based on the identity of the user and the intended recipient

**Resources:**

* [1] https://en.wikipedia.org/wiki/Confused_deputy_problem
* [2] https://security.stackexchange.com/questions/81285/oauth-confused-deputy-access-token-verification-state-parameter
* [3] https://dzone.com/articles/google-oauth-and-confused

## Future Resources

* Security Best Practices for OAuth 2.0: https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15
