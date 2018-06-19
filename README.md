# Password
![Travis CI](https://travis-ci.org/rojo2/password.svg?branch=master)

Library to hash passwords easily using PBKDF2. Well tested and good defaults chosen.

```javascript
import password from "@rojo2/password";

// Hash password
const hashedPassword = await password.hash("plainPassword")

// Verify password
const result = await password.verify("plainPassword", "hashedPassword");
if (result === true) {
  // Password is ok.
} else {
  // Passwords doesn't match.
}
```

Or if you prefer promises:

```javascript
import password from "@rojo2/password";

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
  // ...
});
```

Made with :heart: by ROJO 2 (http://rojo2.com)

