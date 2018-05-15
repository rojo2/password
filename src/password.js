import crypto from "crypto";

/** 
 * Length of the salt generated automatically 
 * @type {number}
 */
const SALT_LENGTH = 512;

/** 
 * Length of the key 
 * @type {number}
 */
const KEY_LENGTH = 4096;

/**
 * Minimum key length.
 * @type {number}
 */
const MIN_KEY_LENGTH = 32;

/** 
 * Number of iterations (PBKDF2) 
 * @type {number}
 */
const ITERATIONS = 100000;

/**
 * Minimum number of iterations. 
 * @type {number}
 */
const MIN_ITERATIONS = 10000;

/** 
 * Digest used to generate the key (PBKDF2). By default `sha512`.
 * @type {string}
 */
const DIGEST = "sha512";

/** 
 * Separator used to separate password parameters. By default ":"
 * @param {string}
 */
const SEPARATOR = ":";

/**
 * Returns a hashed password and all of the parameters used
 * to generate it.
 *
 * @param {string} password - Password
 * @param {string} salt - Salt
 * @param {number} iterations - Iterations
 * @param {number} length - Key length
 * @param {string} digest - Digest used
 * @param {string} [sep=SEPARATOR] - Separator
 * @return {string} - The resulting string
 */
function render(password, salt, iterations, length, digest, sep = SEPARATOR) {
  return [
    password,
    salt,
    iterations,
    length,
    digest
  ].join(sep);
}

/**
 * Returns a promise that when it is resolved it contains a random salt
 * generated using crypto.randomBytes.
 *
 * @param {number} [length=SALT_LENGTH] - Salt length (by default 512)
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
 * @param {string} password - Password
 * @param {string} salt - Salt (if you don't pass this parameter, then a salt will be generated automatically)
 * @param {number} iterations - Iterations
 * @param {number} length - Key length
 * @param {string} digest - Digest
 * @param {string} [sep=SEPARATOR] - Separator (by default ":")
 * @return {Promise}
 */
function pbkdf2(password, salt, iterations, length, digest, sep = SEPARATOR) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, length, digest, (err, key) => {
      if (err) {
        return reject(err);
      }
      return resolve(render(key.toString("hex"), salt, iterations, length, digest, sep));
    });
  });
}

/**
 * Returns a promise that when it is resolved it contains a hashed password
 * and all of the parameters used to generate that hash.
 *
 * @param {string} password - Password (in plain text)
 * @param {string} [salt] - Salt (if not specified, then a random salt is calculated)
 * @param {number} [iterations=ITERATIONS] - Iterations (by default 100000)
 * @param {number} [length=KEY_LENGTH] - Key length (by default 512)
 * @param {string} [digest=DIGEST] - Digest (by default "sha512")
 * @param {string} [sep=SEPARATOR] - Separator
 * @return {Promise<string|Error>} 
 */
function hash(password, salt = null, iterations = ITERATIONS, length = KEY_LENGTH, digest = DIGEST, sep = SEPARATOR) {
  if (!Number.isFinite(length) || length < MIN_KEY_LENGTH) {
    return Promise.reject(new TypeError("Invalid key length"));
  }
  if (!Number.isFinite(iterations) || iterations < MIN_ITERATIONS) {
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
 * @param {string} password - Password (plain text)
 * @param {string} hashedPassword - Hashed Password
 * @param {string} [sep=SEPARATOR] - Separator (by default ":")
 * @return {Promise<boolean|Error>}
 */
function verify(password, hashedPassword, sep = SEPARATOR) {
  const [key, salt, iterations, length, digest] = hashedPassword.split(sep);
  const parsedIterations = parseInt(iterations, 10);
  const parsedLength = parseInt(length, 10);
  if (!Number.isFinite(parsedIterations)) {
    return Promise.reject(new Error("Invalid iterations"));
  }
  if (!Number.isFinite(parsedLength)) {
    return Promise.reject(new Error("Invalid length"));
  }
  if (parsedIterations !== parseFloat(iterations)) {
    return Promise.reject(new Error("Invalid iterations, must be an integer"));
  }
  if (parsedLength !== parseFloat(length)) {
    return Promise.reject(new Error("Invalid key length, must be an integer"));
  }
  return hash(password, salt, parsedIterations, parsedLength, digest)
    .then((verifiedPassword) => verifiedPassword === hashedPassword);
}

export default {
  hash,
  verify
}
