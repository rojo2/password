import { expect } from "chai";
import password from "../src/password";

describe("Password", function() {

  this.timeout(5000);
  
  it("should fail if you don't specify a valid iterations ('10000')", (done) => {

    password.hash("hola", "test", "10000", 32, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });

  it("should fail if you don't specify a valid iterations (Infinity)", (done) => {

    password.hash("hola", "test", Infinity, 32, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });
  
  it("should fail if you don't specify a valid iterations (NaN)", (done) => {

    password.hash("hola", "test", NaN, 32, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });

  it("should fail if you don't specify a valid iterations (true)", (done) => {

    password.hash("hola", "test", true, 32, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });


  it("should fail if you don't specify a valid key length ('32')", (done) => {

    password.hash("hola", "test", 10000, "32", "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });

  it("should fail if you don't specify a valid key length (Infinity)", (done) => {

    password.hash("hola", "test", 10000, Infinity, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });
  
  it("should fail if you don't specify a valid key length (NaN)", (done) => {

    password.hash("hola", "test", 10000, Infinity, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });

  it("should fail if you don't specify a valid key length (true)", (done) => {

    password.hash("hola", "test", 10000, true, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });

  it("should fail if you don't specify a valid digest name", (done) => {

    password.hash("hola", "test", 10000, 32, "").then(() => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });
  
  it("should fail if you don't specify a valid key length", (done) => {

    password.hash("hola", "test", 10000, 0, "sha1").then((result) => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });
  
  it("should fail if you don't specify a valid number of iterations", (done) => {

    password.hash("hola", "test", "1000", 32, "sha1").then((result) => {
      return done(new Error("it should fail"));
    }).catch((err) => {
      return done();
    });

  });

  it("should hash a password", (done) => {
    
    password.hash("hola", "test", 10000, 32, "sha1").then((hashedPassword) => {
      expect(hashedPassword).to.be.equal("3bc3ff808fecfa016e9b62580012ecb9137be9fd8c4cbdecb3cd454e741c6b80:test:10000:32:sha1");
      return done();
    }).catch((err) => {
      return ione(err);
    });

  });

  it("should verify that a previously generated password is correct", (done) => {

    password.verify("hola", "3bc3ff808fecfa016e9b62580012ecb9137be9fd8c4cbdecb3cd454e741c6b80:test:10000:32:sha1").then((result) => {
      expect(result).to.be.equal(true);
      return done();
    }).catch((err) => {
      return done(err); 
    });

  });

});

