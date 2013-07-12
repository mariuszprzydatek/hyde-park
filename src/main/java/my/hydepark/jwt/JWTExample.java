package my.hydepark.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class JWTExample {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {

        // create an instance of KeyPairGenerator suitable for generating RSA keys
        // and initialise it with the bit length of the modulus required
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);

        // generate the key pair
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        // create KeyFactory and RSA Keys Specs
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);

        // generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
        RSAPublicKey publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        RSAPrivateKey privateRsaKey  = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);


        // compose the JWT reserved claim names
        JWTClaimsSet jwtClaims = new JWTClaimsSet();
        jwtClaims.setIssuer("https://my-auth-server.com");
        jwtClaims.setSubject("Mariusz");
        List<String> aud = new ArrayList<>();
        aud.add("https://my-web-app.com");
        aud.add("https://your-web-app.com");
        jwtClaims.setAudience(aud);
        jwtClaims.setExpirationTime(new Date(new Date().getTime() + 1000*60*10));
        jwtClaims.setNotBeforeTime(new Date());
        jwtClaims.setIssueTime(new Date());
        jwtClaims.setJWTID(UUID.randomUUID().toString());

        System.out.println(jwtClaims.toJSONObject());


        // create the JWT header and specify:
        //  RSA-OAEP as the encryption algorithm
        //  128-bit AES/GCM as the encryption method
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

        // create the EncryptedJWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

        // create an RSA encrypter with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);

        // do the actual encryption
        jwt.encrypt(encrypter);

        // serialize to JWT compact form
        String jwtString = jwt.serialize();

        System.out.println(jwtString);


        // in order to read back the data from the token using your private RSA key:
        // parse the JWT text string using EncryptedJWT object
        jwt = EncryptedJWT.parse(jwtString);

        // create a decrypter with the specified private RSA key
        RSADecrypter decrypter = new RSADecrypter(privateRsaKey);

        // do the decryption
        jwt.decrypt(decrypter);

        // print out the claims
        System.out.println("Issuer: " + jwt.getJWTClaimsSet().getIssuer());
        System.out.println("Subject: " + jwt.getJWTClaimsSet().getSubject());
        System.out.println("Audience size: " + jwt.getJWTClaimsSet().getAudience().size());
        System.out.println("Expiration Time: " + jwt.getJWTClaimsSet().getExpirationTime());
        System.out.println("Not Before Time: " + jwt.getJWTClaimsSet().getNotBeforeTime());
        System.out.println("Issue At: " + jwt.getJWTClaimsSet().getIssueTime());
        System.out.println("JWT ID: " + jwt.getJWTClaimsSet().getJWTID());

    }

}