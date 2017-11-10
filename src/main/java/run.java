import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by anthonybertrant on 06/11/2017.
 * Description:
 */
public class run {

    public static void main(String[] args) {
        AES aesCipher = new AES();
        try {
            FileInputStream fis = new FileInputStream(new File("src/main/java/butokuden.jpg"));
            aesCipher.cbcEncrypt(fis, "src/main/java/cdc-secret.jpg");
            fis.close();

            System.out.println("Chiffrement terminer");

            FileInputStream fisCrypted = new FileInputStream(new File("src/main/java/cdc-secret.jpg"));
            aesCipher.cbcDecrypt(fisCrypted, "src/main/java/cdc-decrypted.jpg");
            fis.close();

            System.out.println("Dechiffrement terminer");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
