package cn.linkincloud.sso.demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

public class Application {
    //数字签名
    public static final String KEY_ALGORITHM = "RSA";


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6IjY1MDcwMjkxQHFxLmNvbSIsInVzZXJJZCI6Mn0.YpbUHk7mgS_Zg9_2m2AnOd28mIe7pIsYYtQ5M1-nfFD7DE7Nf03BqgPB-o--OTjF2RmInP2IAFADORnzTsOUKdmRVG6sQpmV3UuJLvW1vg6X8RxLQ-r0-K4-ZspeSCJS5AlEzOgd4CVPLFpsRY6ERZvC5Lhy5fczs-ggEEdUAfrrOa5S5AlD3lHtCAnVVnPj3qASGbZ3WIWVdi0rowXC7X_pCAZTZHzTj93D185Iaa6k0tD0QgdgoeAMU9ysFJEq25jv_Fs_m9BC_EyZPZ-pSNbWdgVzpyZM5Oy19PhnwC_2K-7AwuFhbl7jxPZaUUoL5kYr2b1w_g520XHsTv4keQ";
        String publicKeyStr = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtzKNhb4bXhyuaOIQM3OI\n" +
                "3cGRZg9+kIZNmkAe3Bj9fapkFkakUHlBC/+0mI2gkIA0gCBLI2FmFpKYu9d6kC73\n" +
                "Fi4/i6dz47rhMy9mqVnC5LEBBSQ3MTF7NCRnTt2P2oYgas+VaHj+PWlNRsb2xnHJ\n" +
                "hFRfGQ90YJox5J1bXPaftR8wfLqeJXdf3+PpxhBLj8WKt0MTWAcnTXy1U7djoIM8\n" +
                "kTsutkBfiBnTXOejwA2jRH1v0TrPZScG7bjaxKfTiZi3la6AQ1H5/6nC+vjBWVUg\n" +
                "+fGtXnr93+OYCob9pPROD1R1lClx4PqCq4qSxf9HFH/AEHW+pigXA06q/jJqqCcK\n" +
                "swIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(publicKeyStr);//Get the key instance

        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        JWTVerifier verifier = JWT.require(algorithm)
                .build();
        DecodedJWT jwt = verifier.verify(token);

        Map<String, Claim> claims = jwt.getClaims();
        System.out.println("userName:" + claims.get("userName"));
        System.out.println("userId:" + claims.get("userId"));
    }

    private static byte[] parsePEM(String data) throws IOException {
        try (PemReader reader = new PemReader(new StringReader(data))) {
            PemObject pemObject = reader.readPemObject();
            return pemObject.getContent();
        }
    }

    private static PublicKey getPublicKey(String data) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] content = parsePEM(data);

        KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(content);
        return kf.generatePublic(keySpec);
    }
}
