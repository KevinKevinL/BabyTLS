import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.math.BigInteger;

public class BabyTLSCracker {
    private static final String HOST = "localhost";
    private static final int SERVER_PORT = 8888;
    private static final int PROXY_PORT = 8889;
    private static final BigInteger p = BigInteger.valueOf(23);
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
                    System.out.println("Client connected to proxy");
                    System.out.println("Proxy connected to server");

                    // Relay client's public key to server
                    System.out.println("Waiting for client public key...");
                    String clientPublicKeyStr = clientIn.readLine();
                    System.out.println("Received client public key: " + clientPublicKeyStr);
                    System.out.println("Forwarding client public key to server...");
                    serverOut.println(clientPublicKeyStr);
                    BigInteger clientPublicKey = new BigInteger(clientPublicKeyStr);

                    // Relay server's public key to client
                    System.out.println("Waiting for server public key...");
                    String serverPublicKeyStr = serverIn.readLine();
                    System.out.println("Received server public key: " + serverPublicKeyStr);
                    System.out.println("Forwarding server public key to client...");
                    clientOut.println(serverPublicKeyStr);
                    BigInteger serverPublicKey = new BigInteger(serverPublicKeyStr);

                    System.out.println("Intercepted public keys:");
                    System.out.println("Client: " + clientPublicKey);
                    System.out.println("Server: " + serverPublicKey);

                    // Crack private keys
                    System.out.println("Starting to crack private keys...");
                    long startTime = System.currentTimeMillis();

                    BigInteger clientPrivateKey = crackPrivateKey(clientPublicKey);
                    BigInteger serverPrivateKey = crackPrivateKey(serverPublicKey);

                    long endTime = System.currentTimeMillis();

                    System.out.println("Cracked private keys:");
                    System.out.println("Client: " + clientPrivateKey);
                    System.out.println("Server: " + serverPrivateKey);
                    System.out.println("Time taken to crack: " + (endTime - startTime) + " ms");

                    // Derive session key
                    BigInteger sharedSecret = serverPublicKey.modPow(clientPrivateKey, p);
                    byte[] keyBytes = deriveKey(sharedSecret.toByteArray());
                    SecretKeySpec sessionKey = new SecretKeySpec(keyBytes, "AES");

                    // Relay and intercept messages
                    String message;
                    while ((message = clientIn.readLine()) != null) {
                        System.out.println("Intercepted encrypted message from client: " + message);
                        String decryptedMessage = decrypt(message, sessionKey);
                        System.out.println("Decrypted message: " + decryptedMessage);

                        System.out.println("Forwarding encrypted message to server...");
                        serverOut.println(message);

                        String serverResponse = serverIn.readLine();
                        if (serverResponse != null) {
                            System.out.println("Intercepted encrypted response from server: " + serverResponse);
                            String decryptedResponse = decrypt(serverResponse, sessionKey);
                            System.out.println("Decrypted response: " + decryptedResponse);

                            System.out.println("Forwarding encrypted response to client...");
                            clientOut.println(serverResponse);
                        } else {
                            System.out.println("Server closed the connection.");
                            break;
                        }
                    }

                    System.out.println("Client closed the connection.");
                } catch (Exception e) {
                    System.out.println("Error occurred during communication: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            System.out.println("Could not listen on port " + PROXY_PORT);
            e.printStackTrace();
        }
    }

    private static BigInteger crackPrivateKey(BigInteger publicKey) {
        System.out.println("Cracking private key for public key: " + publicKey);
        for (BigInteger i = BigInteger.ONE; i.compareTo(p) < 0; i = i.add(BigInteger.ONE)) {
            if (g.modPow(i, p).equals(publicKey)) {
                return i;
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