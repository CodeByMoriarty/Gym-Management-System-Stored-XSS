# CVE Report: Cross-Site Scripting (XSS) Vulnerability in Gym Management System

## Overview
- **Vulnerability Type**: Cross-Site Scripting (XSS)  
- **Product Name**: Gym Management System  
- **Vendor**: PHPGurukul  
- **Affected Version**: All versions up to the discovery date  
- **Date Reported**: January 11, 2025  
- **Discoverer**: CodeByMoriarty (AndrewL)  

---

## Description
The Gym Management System provided by PHPGurukul is vulnerable to a stored Cross-Site Scripting (XSS) attack. This issue occurs in the **"Update Profile"** feature available to logged-in users. The vulnerability arises due to improper sanitization and validation of user-provided input in the **Address field** of the profile update form.

Attackers can exploit this vulnerability to inject malicious HTML or JavaScript payloads into the Address field, which will then be executed in the browser of any user viewing the profile or relevant content.

---

## Vulnerable Endpoint
- **Endpoint**: `profile.php` (Update Profile functionality)  
- **Affected Field**: Address  

---

## Steps to Reproduce
1. **Log in** to the Gym Management System as a regular user.  
2. Navigate to the **"Update Profile"** section.  
3. In the Address field, input the following malicious payload:  
    ```html
    <div class="test">XSS<input type="text" value="XSS"></div>
    "><h1>XSS</h1>
    <img src="x" onerror="alert('XSS')">
    ```
4. Save the changes.  
5. View the updated profile. The stored payload will execute, triggering a `JavaScript alert('XSS')` popup.  

---

## Impact
- **Type of Vulnerability**: Stored XSS  
- **Severity**: High  

### Impact Details:
- Execution of arbitrary JavaScript code in the context of the affected user’s browser.  
- Potential theft of session cookies, enabling session hijacking.  
- Phishing attacks or injection of malicious links.  
- Defacement of the application’s user interface.  

---

## Technical Analysis
The application does not properly sanitize or validate user-provided input in the Address field. This allows an attacker to inject malicious HTML or JavaScript payloads, which are stored in the database and subsequently executed in the browser whenever the affected content is rendered.

---

## Mitigation
1. **Input Validation**:
    - Ensure all user inputs are sanitized to remove potentially harmful characters such as `<`, `>`, `"`, `\`, etc.
    - Use server-side input validation libraries to enforce strict rules.

2. **Output Encoding**:
    - Apply context-specific escaping when rendering user-generated content, such as using `htmlspecialchars()` in PHP to encode HTML entities.

3. **Content Security Policy (CSP)**:
    - Implement a CSP header to restrict the execution of inline scripts.  
    - Example CSP header:  
      ```
      Content-Security-Policy: script-src 'self'; object-src 'none';
      ```

4. **Prepared Statements**:
    - Always use prepared statements for database interactions to avoid SQL Injection risks.

5. **Regular Security Audits**:
    - Conduct periodic security audits and penetration testing to identify and patch vulnerabilities proactively.

---

## Proof of Concept (PoC)

### Payload:
```html
<div class="test">XSS<input type="text" value="XSS"></div>
"><h1>XSS</h1>
<img src="x" onerror="alert('XSS')">
```

### Result:

Upon saving the malicious input in the Address field, the payload is executed whenever the profile is viewed, triggering an XSS alert popup.


### Visual Proof
https://github.com/CodeByMoriarty/Gym-Management-System-Stored-XSS/blob/main/gym.png
