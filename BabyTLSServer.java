import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.math.BigInteger;

public class BabyTLSServer {
    private static final int PORT = 8888;
    private static final BigInteger p = BigInteger.valueOf(23);
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

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                out = new PrintWriter(socket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // 执行密钥交换
                BigInteger privateKey = new BigInteger(4, new SecureRandom());
                BigInteger publicKey = g.modPow(privateKey, p);

                System.out.println("Waiting for client's public key...");
                // 接收客户端的公钥
                BigInteger clientPublicKey = new BigInteger(in.readLine());
                System.out.println("Received client's public key: " + clientPublicKey);

                System.out.println("Sending server's public key: " + publicKey);
                // 发送公钥给客户端
                out.println(publicKey);

                // 计算共享密钥
                BigInteger sharedSecret = clientPublicKey.modPow(privateKey, p);

                // 派生会话密钥
                byte[] keyBytes = deriveKey(sharedSecret.toByteArray());
                sessionKey = new SecretKeySpec(keyBytes, "AES");

                System.out.println("Secure connection established with client");

                // 主通信循环
                String line;
                while ((line = in.readLine()) != null) {
                    String decrypted = decrypt(line);
                    System.out.println("Received message: " + decrypted);

                    String response = encrypt("Server received: " + decrypted);
                    System.out.println("Sending response: " + response);
                    out.println(response);
                }

                System.out.println("Client disconnected");
                socket.close();
            } catch (Exception e) {
                System.out.println("Error in client handler: " + e.getMessage());
                e.printStackTrace();
            }
        }

        // ... (其他方法保持不变)

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