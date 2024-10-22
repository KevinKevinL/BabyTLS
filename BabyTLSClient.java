import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.util.Base64;
import java.math.BigInteger;

public class BabyTLSClient {
    private static final String HOST = "localhost";
    private static final int PORT = 8889;
    // 使用一个适中的素数，足够展示安全特性但又可以在合理时间内破解
    private static final BigInteger p = new BigInteger("137", 10);
    private static final BigInteger g = BigInteger.valueOf(5);

    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private SecretKeySpec sessionKey;
    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    private PublicKey serverRsaPublicKey;

    public static void main(String[] args) {
        BabyTLSClient client = new BabyTLSClient();
        client.start();
    }

    public void start() {
        try {
            // 生成RSA密钥对
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            rsaPrivateKey = pair.getPrivate();
            rsaPublicKey = pair.getPublic();

            socket = new Socket(HOST, PORT);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // 执行密钥交换
            BigInteger privateKey = new BigInteger(32, new SecureRandom());
            BigInteger publicKey = g.modPow(privateKey, p);

            // 发送RSA公钥和DH公钥
            String publicKeyStr = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded()) + 
                                ":" + publicKey.toString();
            out.println(publicKeyStr);

            // 接收服务器的RSA公钥和DH公钥
            String[] serverKeys = in.readLine().split(":");
            byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverKeys[0]);
            serverRsaPublicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));
            BigInteger serverPublicKey = new BigInteger(serverKeys[1]);

            // 计算共享密钥
            BigInteger sharedSecret = serverPublicKey.modPow(privateKey, p);

            // 派生会话密钥
            byte[] keyBytes = deriveKey(sharedSecret.toByteArray());
            sessionKey = new SecretKeySpec(keyBytes, "AES");

            System.out.println("Secure connection established");

            // 发送加密消息
            sendMessage("Hello, Server!");
            sendMessage("This is a secret message.");

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendMessage(String message) throws Exception {
        // 加密消息
        String encrypted = encrypt(message);
        // 签名
        String signature = sign(message);
        // 发送加密消息和签名
        out.println(encrypted + ":" + signature);
        
        // 接收响应
        String response = in.readLine();
        if (response != null) {
            String[] parts = response.split(":");
            if (parts.length == 2) {
                String decrypted = decrypt(parts[0]);
                boolean validSignature = verify(decrypted, parts[1]);
                System.out.println("Server response: " + decrypted + 
                                 " (Signature valid: " + validSignature + ")");
            }
        }
    }

    private String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(rsaPrivateKey);
        signature.update(message.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private boolean verify(String message, String signatureStr) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(serverRsaPublicKey);
        signature.update(message.getBytes());
        return signature.verify(Base64.getDecoder().decode(signatureStr));
    }

    private static byte[] deriveKey(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(sharedSecret);
    }

    private String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }

    private String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)));
    }
}