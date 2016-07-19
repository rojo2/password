const {expect} = require("chai");
const password = require("../password");

describe("Password", function() {

  this.timeout(5000);

  it("should fail if you don't specify a valid digest name", (done) => {

    password.hash("hola", "test", 10000, 32, "").then(() => {
      done(new Error("it should fail"));
    }).catch((err) => {
      expect(err.toString()).to.be.equal("TypeError: Bad digest name");
      done();
    });

  });
  
  it("should fail if you don't specify a valid key length", (done) => {

    password.hash("hola", "test", 10000, 0, "sha1").then((result) => {
      done(new Error("it should fail"));
    }).catch((err) => {
      expect(err.toString()).to.be.equal("TypeError: Invalid key length");
      done();
    });

  });
  
  it("should fail if you don't specify a valid number of iterations", (done) => {

    password.hash("hola", "test", "1000", 32, "sha1").then((result) => {
      done(new Error("it should fail"));
    }).catch((err) => {
      expect(err.toString()).to.be.equal("TypeError: Invalid number of iterations");
      done();
    });

  });

  it("should hash a password", (done) => {
    
    password.hash("hola", "test", 10000, 32, "sha1").then((hashedPassword) => {
      expect(hashedPassword).to.be.equal("3bc3ff808fecfa016e9b62580012ecb9137be9fd8c4cbdecb3cd454e741c6b80:test:10000:32:sha1");
      done();
    }).catch((err) => {
      done(err);
    });

  });

  it("should verify that a previously generated password is correct", (done) => {

    password.verify("hola", "3bc3ff808fecfa016e9b62580012ecb9137be9fd8c4cbdecb3cd454e741c6b80:test:10000:32:sha1").then((result) => {
      expect(result).to.be.equal(true);
      done();
    }).catch((err) => {
      done(err); 
    });

  });

});

