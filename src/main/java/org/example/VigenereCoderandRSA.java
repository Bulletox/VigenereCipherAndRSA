package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;


public class VigenereCoderandRSA {


/*codificar Vigenere*/
    static String encrypt(String text, String key) {
        String res = "";
        text = text.toUpperCase();
        for (int i = 0, j = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 'A' || c > 'Z') {
                continue;
            }
            res += (char) ((c + key.charAt(j) - 2 * 'A') % 26 + 'A');
            j = ++j % key.length();
        }
        return res;
    }
    /*desencriptar Vigenere*/
    static String decrypt(String text, String key) {
        String res = "";
        text = text.toUpperCase();
        for (int i = 0, j = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 'A' || c > 'Z') {
                continue;
            }
            res += (char) ((c - key.charAt(j) + 26) % 26 + 'A');
            j = ++j % key.length();
        }
        return res;
    }
    /*Codificacion RSA */
    private PrivateKey privateKey;
    private PublicKey publicKey;

/*generamos la clave public y privada*/
    public void generateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

/*encriptamos la string que paso previamente por vigenere*/
    public String encryptRSA(String txtencrypt) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] secretMessageBytes = txtencrypt.getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }
/*desencriptamos lo codificado con rsa*/
    public String decryptRSA(String txtencryptRSA) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedMessageBytes = Base64.getDecoder().decode(txtencryptRSA);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        return new String(decryptedMessageBytes, StandardCharsets.US_ASCII);
    }

/*Menu desde donde se redirecciona las peticiones del usuario*/
    public void menu() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        VigenereCoderandRSA patata = new VigenereCoderandRSA();
        String srcOri = "";
        String key = "";
        String enc = "";
        String encRSA = "";
        String desRSA = "";
        while (true) {
            System.out.println("--------<MENU>--------");
            System.out.println("1. Encriptar con Vigenere");
            System.out.println("2. Generar claves Publicas y Privadas");
            System.out.println("3. Encriptar con RSA");
            System.out.println("4. Desencriptar con RSA");
            System.out.println("5. Desencriptar con Vigenere");
            System.out.println("6. AUTO CODE AND DECODE debugMode");
            System.out.println("7. Salir del programa");
            System.out.println("-------<Opción>-------");

            int op = Integer.parseInt(String.valueOf(sctxt().charAt(0)));

            switch (op){
                case 1:
                    System.out.println("Ingrese el texto para encriptar con Vigenere: ");
                    srcOri = sctxt();
                    System.out.println("Ingrese la key");
                    key = sctxt().toUpperCase();
                    enc = encrypt(srcOri, key);
                    System.out.println("Texto encrptado con Vigenere: "+ enc);
                    break;
                case 2:
                    /*Simulamos la creacion de las claves*/
                    try {
                        System.out.println("Claves creadas");
                        System.out.println(patata.privateKey);
                        System.out.println(patata.publicKey);
                    }catch (Exception e){
                        System.out.println("Imposible generar las claves");
                    }
                    break;
                case 3:
                    if (patata.publicKey == null){
                        System.out.println("Claves publica no generada.");
                    }else{
                        try {
                            System.out.println("Codificando texto codificado con VIG + RSA");
                            encRSA = patata.encryptRSA(enc);
                            System.out.println(encRSA);
                        }catch (Exception  e){
                            System.out.println("Imposible codificar");
                        }
                    }
                    break;
                case 4:
                    /*decodificamos RSA*/
                    if (patata.privateKey == null) {
                        System.out.println("Claves privada no generada.");
                    } else {
                        try {
                            System.out.println("Decodificando texto codificado con VIG - RSA");
                            desRSA = patata.decryptRSA(encRSA);
                            System.out.println("Texto decodificado: "+ desRSA);
                        }catch (Exception  e){
                            System.out.println("Imposible decodificar");
                        }
                    }
                    break;
                case 5:
                    System.out.println(decrypt(desRSA,key));
                    break;
                case 6:
                    /*Modo de debug para ver ver si todo va bien*/
                    System.out.println("Ingrese el texto para encriptar con Vigenere: ");
                    srcOri = sctxt();
                    System.out.println("Ingrese la key");
                    key = sctxt().toUpperCase();
                    enc = encrypt(srcOri, key);
                    System.out.println("Texto encrptado con Vigenere: "+ enc);
                    patata.generateKey();
                    System.out.println("Claves creadas");
                    //System.out.println(patata.privateKey);
                    //System.out.println(patata.publicKey);
                    System.out.println("Codificando texto codificado con VIG + RSA");
                    encRSA = patata.encryptRSA(enc);
                    System.out.println(encRSA);
                    System.out.println("Decodificando texto codificado con VIG - RSA");
                    desRSA = patata.decryptRSA(encRSA);
                    System.out.println("Texto decodificado: "+ desRSA);
                    System.out.println("Texto decodificado del todo "+decrypt(desRSA,key));
                    break;
                case 7:
                    System.out.println("Saliendo del programa. ¡Hasta luego!");
                    System.exit(0);
                    break;
                default:
                    System.out.println("Opción no válida");
                    break;
            }
        }
    }
    //entrada de datos universal
    static String sctxt(){
        Scanner sc = new Scanner(System.in);
        String data = sc.nextLine();
        return data;
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        VigenereCoderandRSA patata = new VigenereCoderandRSA();
        //generamos la key publica y privada de antemano para evitar errores
        patata.generateKey();
        patata.menu();
    }
}