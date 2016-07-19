const crypto = require("crypto");

/** Length of the salt generated automatically */
const SALT_LENGTH = 512;

/** Length of the key */
const KEY_LENGTH = 512;

/** Number of iterations (PBKDF2) */
const ITERATIONS = 100000;

/** Digest used to generate the key (PBKDF2) */
const DIGEST = 'sha512';

/** Separator used to separate password parameters */
const SEPARATOR = ':';

/**
 * Returns a hashed password and all of the parameters used
 * to generate it.
 * 
 * @param {String} password
 * @param {String} salt
 * @param {Number} iterations
 * @param {Number} length
 * @param {String} digest
 * @return {String} The resulting string
 */
function render(password, salt, iterations, length, digest) {
  return `${password}${SEPARATOR}${salt}${SEPARATOR}${iterations}${SEPARATOR}${length}${SEPARATOR}${digest}`;
}

/**
 * Returns a promise that when it is resolved it contains a random salt
 * generated using crypto.randomBytes.
 * 
 * @param {Number} length
 * @return {Promise}
 */
function createSalt(length = SALT_LENGTH) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(length, (err, salt) => {
      if (err) {
        return reject(err);
      }
      return resolve(salt.toString("hex"));
    });
  });
}

/**
 * Returns a promise that when it is resolved it contains a hashed password and
 * all of the parameters passed to this function.
 *
 * @param {String} password
 * @param {String} salt
 * @param {Number} iterations
 * @param {Number} length
 * @param {String} digest
 * @return {Promise}
 */
function pbkdf2(password, salt, iterations, length, digest) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, length, digest, (err, key) => {
      if (err) {
        return reject(err);
      }
      return resolve(render(key.toString("hex"), salt, iterations, length, digest));
    });
  });
}

/**
 * Returns a promise that when it is resolved it contains a hashed password 
 * and all of the parameters used to generate that hash.
 *
 * @param {String} password
 * @param {String} salt
 * @param {Number} iterations
 * @param {Number} length
 * @param {String} digest
 * @return {Promise}
 */
function hash(password, salt = null, iterations = ITERATIONS, length = KEY_LENGTH, digest = DIGEST) {
  if (typeof length !== "number" || length < 32) {
    return Promise.reject(new TypeError("Invalid key length"));
  }

  if (typeof iterations !== "number" || iterations < 10000) {
    return Promise.reject(new TypeError("Invalid number of iterations"));
  }

  if (!salt) {
    return createSalt().then((salt) => pbkdf2(password, salt, iterations, length, digest));
  }
  return pbkdf2(password, salt, iterations, length, digest);
}

/**
 * Returns a promise that when it is resolved it contains a boolean value that
 * indicates if the password is ok or not.
 *
 * @param {String} password
 * @param {String} hashedPassword
 * @return {Promise}
 */
function verify(password, hashedPassword) {
  const [key, salt, iterations, length, digest] = hashedPassword.split(SEPARATOR);
  return hash(password, salt, parseInt(iterations, 10), parseInt(length, 10), digest).then((verifiedPassword) => verifiedPassword === hashedPassword);
}

module.exports = { hash, verify };
