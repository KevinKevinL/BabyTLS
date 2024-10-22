import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.math.BigInteger;

public class BabyTLSCracker {
    private static final String HOST = "localhost";
    private static final int SERVER_PORT = 8888;
    private static final int PROXY_PORT = 8889;
    private static final BigInteger p = new BigInteger("137", 10);
    private static final BigInteger g = BigInteger.valueOf(5);

    public static void main(String[] args) {
        try (ServerSocket proxyServer = new ServerSocket(PROXY_PORT)) {
            System.out.println("Proxy is listening on port " + PROXY_PORT);

            while (true) {
                try (
                    Socket clientSocket = proxyServer.accept();
                    Socket serverSocket = new Socket(HOST, SERVER_PORT);
                    BufferedReader clientIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                    PrintWriter clientOut = new PrintWriter(clientSocket.getOutputStream(), true);
                    BufferedReader serverIn = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
                    PrintWriter serverOut = new PrintWriter(serverSocket.getOutputStream(), true)
                ) {
                    System.out.println("\nNew connection established");
                    System.out.println("Client connected to proxy");
                    System.out.println("Proxy connected to server");

                    // 转发和截获密钥交换过程
                    String clientKeyMsg = clientIn.readLine();
                    String[] clientKeys = clientKeyMsg.split(":");
                    serverOut.println(clientKeyMsg);
                    String clientDHPublicKeyStr = clientKeys[1];
                    BigInteger clientDHPublicKey = new BigInteger(clientDHPublicKeyStr);

                    String serverKeyMsg = serverIn.readLine();
                    String[] serverKeys = serverKeyMsg.split(":");
                    clientOut.println(serverKeyMsg);
                    String serverDHPublicKeyStr = serverKeys[1];
                    BigInteger serverDHPublicKey = new BigInteger(serverDHPublicKeyStr);

                    System.out.println("\nIntercepted DH public keys:");
                    System.out.println("Client: " + clientDHPublicKey);
                    System.out.println("Server: " + serverDHPublicKey);

                    // 使用优化的方法破解私钥
                    System.out.println("\nStarting to crack private keys...");
                    long startTime = System.currentTimeMillis();

                    System.out.println("Cracking client private key...");
                    BigInteger clientPrivateKey = crackDHPrivateKey(clientDHPublicKey);
                    System.out.println("Successfully cracked client private key: " + clientPrivateKey);

                    System.out.println("Cracking server private key...");
                    BigInteger serverPrivateKey = crackDHPrivateKey(serverDHPublicKey);
                    System.out.println("Successfully cracked server private key: " + serverPrivateKey);

                    long endTime = System.currentTimeMillis();
                    System.out.println("Time taken to crack: " + (endTime - startTime) + " ms");

                    // 计算共享密钥
                    BigInteger sharedSecret = serverDHPublicKey.modPow(clientPrivateKey, p);
                    System.out.println("Computed shared secret: " + sharedSecret);
                    byte[] keyBytes = deriveKey(sharedSecret.toByteArray());
                    SecretKeySpec sessionKey = new SecretKeySpec(keyBytes, "AES");

                    // 转发和解密消息
                    String message;
                    while ((message = clientIn.readLine()) != null) {
                        System.out.println("\nIntercepted client message: " + message);
                        serverOut.println(message);
                        
                        String[] messageParts = message.split(":");
                        if (messageParts.length >= 1) {
                            try {
                                String decryptedMessage = decrypt(messageParts[0], sessionKey);
                                System.out.println("Decrypted message: " + decryptedMessage);
                            } catch (Exception e) {
                                System.out.println("Failed to decrypt message: " + e.getMessage());
                            }
                        }

                        String response = serverIn.readLine();
                        if (response != null) {
                            System.out.println("Intercepted server response: " + response);
                            String[] responseParts = response.split(":");
                            if (responseParts.length >= 1) {
                                try {
                                    String decryptedResponse = decrypt(responseParts[0], sessionKey);
                                    System.out.println("Decrypted response: " + decryptedResponse);
                                } catch (Exception e) {
                                    System.out.println("Failed to decrypt response: " + e.getMessage());
                                }
                            }
                            clientOut.println(response);
                        }
                    }
                } catch (Exception e) {
                    System.out.println("Error in connection: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static BigInteger crackDHPrivateKey(BigInteger publicKey) {
        System.out.println("Cracking private key for public key: " + publicKey);
        
        // 对于小的素数p，直接使用暴力搜索更可靠
        BigInteger maxExponent = p;
        BigInteger attempt = BigInteger.ZERO;
        
        while (attempt.compareTo(maxExponent) < 0) {
            if (g.modPow(attempt, p).equals(publicKey)) {
                return attempt;
            }
            attempt = attempt.add(BigInteger.ONE);
            
            // 每1000次尝试显示一个进度标记
            if (attempt.mod(BigInteger.valueOf(1000)).equals(BigInteger.ZERO)) {
                System.out.print(".");
            }
        }
        
        throw new RuntimeException("Failed to crack private key");
    }

    private static byte[] deriveKey(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(sharedSecret);
    }

    private static String decrypt(String encryptedMessage, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)));
    }
}