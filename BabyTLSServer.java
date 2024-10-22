import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.math.BigInteger;

public class BabyTLSServer {
    private static final int PORT = 8888;
    private static final BigInteger p = new BigInteger("137", 10);
    private static final BigInteger g = BigInteger.valueOf(5);

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is listening on port " + PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New client connected");

                new ClientHandler(socket).start();
            }
        } catch (IOException ex) {
            System.out.println("Server exception: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {
        private Socket socket;
        private PrintWriter out;
        private BufferedReader in;
        private SecretKeySpec sessionKey;
        private PrivateKey rsaPrivateKey;
        private PublicKey rsaPublicKey;
        private PublicKey clientRsaPublicKey;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                out = new PrintWriter(socket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // 生成 RSA 密钥对
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair pair = keyGen.generateKeyPair();
                rsaPrivateKey = pair.getPrivate();
                rsaPublicKey = pair.getPublic();

                // 生成 DH 密钥
                BigInteger privateKey = new BigInteger(32, new SecureRandom());
                BigInteger publicKey = g.modPow(privateKey, p);

                System.out.println("Waiting for client's public key...");
                // 接收客户端的公钥
                String[] clientKeys = in.readLine().split(":");
                byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientKeys[0]);
                clientRsaPublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(clientPublicKeyBytes));
                BigInteger clientPublicKey = new BigInteger(clientKeys[1]);
                System.out.println("Received client's DH public key: " + clientPublicKey);

                // 发送服务器的公钥
                String serverPublicKeyStr = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded()) + 
                                         ":" + publicKey.toString();
                out.println(serverPublicKeyStr);
                System.out.println("Sent server's DH public key: " + publicKey);

                // 计算共享密钥
                BigInteger sharedSecret = clientPublicKey.modPow(privateKey, p);
                System.out.println("Computed shared secret: " + sharedSecret);

                // 派生会话密钥
                byte[] keyBytes = deriveKey(sharedSecret.toByteArray());
                sessionKey = new SecretKeySpec(keyBytes, "AES");

                System.out.println("Secure connection established");

                // 主通信循环
                String line;
                while ((line = in.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts.length == 2) {
                        String decrypted = decrypt(parts[0]);
                        boolean validSignature = verify(decrypted, parts[1]);
                        System.out.println("Received message: " + decrypted + 
                                         " (Signature valid: " + validSignature + ")");

                        String response = "Server received: " + decrypted;
                        String encrypted = encrypt(response);
                        String signature = sign(response);
                        out.println(encrypted + ":" + signature);
                    }
                }

                System.out.println("Client disconnected");
                socket.close();
            } catch (Exception e) {
                System.out.println("Error in client handler: " + e.getMessage());
                e.printStackTrace();
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
            signature.initVerify(clientRsaPublicKey);
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
}