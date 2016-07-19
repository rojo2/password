# Password

This hashes a password using PBKDF2.

```javascript
const password = require("password");

// Hash password
password.hash("plainPassword").then((hashedPassword) => {
  // ... do something with the hashed password (like saving it in a mongodb object) ...
}).catch((error) => {
  // ...
});

// Verify password
password.verify("plainPassword", "hashedPassword").then((result) => {
	if (result === true) {
		// Password is ok.
	} else {
		// Passwords doesn't match.
	}
}).catch((error) => {

});
```

Made with ❤ by ROJO 2 (http://rojo2.com)

