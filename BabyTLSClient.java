import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.math.BigInteger;

public class BabyTLSClient {
    private static final String HOST = "localhost";
    private static final int PORT = 8889;
    private static final BigInteger p = BigInteger.valueOf(23);
    private static final BigInteger g = BigInteger.valueOf(5);

    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private SecretKeySpec sessionKey;

    public static void main(String[] args) {
        BabyTLSClient client = new BabyTLSClient();
        client.start();
    }

    public void start() {
        try {
            socket = new Socket(HOST, PORT);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // 执行密钥交换
            BigInteger privateKey = new BigInteger(4, new SecureRandom());
            BigInteger publicKey = g.modPow(privateKey, p);

            // 发送公钥给服务器
            out.println(publicKey);

            // 接收服务器的公钥
            BigInteger serverPublicKey = new BigInteger(in.readLine());

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
        String encrypted = encrypt(message);
        out.println(encrypted);
        String response = in.readLine();
        String decrypted = decrypt(response);
        System.out.println("Server response: " + decrypted);
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