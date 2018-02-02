# Environment
I checked it works in

- Burp 1.7.30
- Mac OS Sierra
- Jython 2.7.0
- java version "1.8.0_144"
- Java(TM) SE Runtime Environment (build 1.8.0_144-b01)
- Java HotSpot(TM) 64-Bit Server VM (build 25.144-b01, mixed mode)

# What it makes to enable us to do
1. Store CSRF Tokens which satisfy the preset regex from macro/proxy responses automatically.
2. Send CSRF Tokens with the stored token with a custom HTTP Header (this feature is not available with vanilla Burp Suite Professional).

# How to use

1. Install and enable this script with your Burp Suite Professional.
2. Set the scope in which you want to send HTTP Header with CSRF Token by ight-clicking in the Proxy tab or directly inputting regexp. (e.g. ```^https://shift-js.info:433/*``` . please make sure every scope includes a port.)
3. Set the regexp which matches the source of CSRF Tokens of the website you're testing.
4. If necessary, set the custom header name with which you want to send a token in the HTTP header.
