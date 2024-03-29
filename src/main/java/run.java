import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by anthonybertrant on 06/11/2017.
 * Description:
 */
public class run {

    private static byte[] NULL_KEY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    public static void main(String[] args) {

        if(args.length == 0){
            AES aesCipher = new AES();
            aesCipher.encryption();
            byte[] res = aesCipher.getState();

            System.out.println("Resultat: " + toHex(res));

        }else if (args.length == 1){
            switch (args[0]) {
                case "-e": {

                    //Mode encryption
                    AES aesCipher = new AES();
                    aesCipher.encryption();

                    byte[] res = aesCipher.getState();
                    System.out.println("Résultat: " + toHex(res));

                    break;
                }
                case "-d": {

                    //Mode decryption
                    AES aesCipher = new AES();
                    aesCipher.decryption();

                    byte[] res = aesCipher.getState();
                    System.out.println("Résultat: " + toHex(res));

                    break;
                }
                default:
                    System.out.println("Erreur argument");
                    System.exit(-1);
            }

        }else if(args.length == 2){
            switch (args[0]) {
                case "-e": {
                    AES aesCipher = new AES();

                    try {
                        FileInputStream fis = new FileInputStream(new File(args[1]));
                        String cible = "aes-" + args[1];
                        System.out.println("Chiffrement de " + args[1] + " en " + cible);
                        aesCipher.cbcEncrypt(fis, cible, NULL_KEY);

                        fis.close();

                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    break;
                }
                case "-d": {
                    AES aesCipher = new AES();
                    try {
                        FileInputStream fisCrypted = new FileInputStream(new File(args[1]));
                        String cible = "aes-" + args[1];
                        aesCipher.cbcDecrypt(fisCrypted, cible, NULL_KEY);
                        fisCrypted.close();

                        System.out.println("Déchiffrement de " + args[1] + " en " + cible);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    break;
                }
                default:
                    System.out.println("Erreur argument");
                    System.exit(-1);
            }
        } else if(args.length == 3){
            switch (args[0]){
                case "-e": {
                    AES aesCipher = new AES();

                    MD5 md5 = new MD5();
                    byte[] key = md5.generateMD5(args[2]);

                    try {
                        FileInputStream fis = new FileInputStream(new File(args[1]));
                        String cible = "aes-" + args[1];
                        System.out.println("La clef utilisée est: " + toHex(key));
                        System.out.println("Chiffrement de " + args[1] + " en " + cible);
                        aesCipher.cbcEncrypt(fis, cible, key);

                        fis.close();

                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    break;
                }
                case "-d": {

                    AES aesCipher = new AES();

                    MD5 md5 = new MD5();
                    byte[] key = md5.generateMD5(args[2]);

                    try {
                        FileInputStream fisCrypted = new FileInputStream(new File(args[1]));
                        String cible = "aes-" + args[1];
                        aesCipher.cbcDecrypt(fisCrypted, cible, key);
                        fisCrypted.close();
                        System.out.println("La clef utilisée est: " + toHex(key));
                        System.out.println("Déchiffrement de " + args[1] + " en " + cible);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    break;
                }
                default:
                    System.out.println("Erreur argument");
                    System.exit(-1);
            }
        }
    }

    public static String toHex(byte[] donnees) {
        return "0x" + javax.xml.bind.DatatypeConverter.printHexBinary(donnees);
    }
}
