import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Simple DNIe signer using Java SunMSCAPI (Windows CAPI).
 * Avoids CNG to work around the DNIe CSP's CAPI-only requirement.
 * 
 * Usage: java CAPISigner <thumbprint> <data_base64>
 * Output: SIG:<signature_base64>
 */
public class CAPISigner {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("ERR:Usage: CAPISigner <thumbprint> <data_base64>");
            System.exit(1);
        }

        // Force SunMSCAPI (CAPI, not CNG)
        Security.setProperty("jdk.crypto.mscapi.useSunMSCAPI", "true");

        String thumbprint = args[0].toUpperCase();
        byte[] data = Base64.getDecoder().decode(args[1].trim());

        // Open Windows-MY keystore (CAPI)
        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        // Find certificate by thumbprint
        PrivateKey privateKey = null;
        boolean found = false;

        for (String alias : java.util.Collections.list(ks.aliases())) {
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            if (cert == null) continue;

            String certThumbprint = getThumbprint(cert);
            if (certThumbprint.equals(thumbprint)) {
                privateKey = (PrivateKey) ks.getKey(alias, null);
                found = true;
                break;
            }
        }

        if (!found) {
            System.out.println("ERR:Certificate not found: " + thumbprint);
            System.exit(1);
        }

        if (privateKey == null) {
            System.out.println("ERR:Private key is null (PIN may be required)");
            System.exit(1);
        }

        // Sign using SunMSCAPI (CAPI-based, not CNG)
        Signature sig = Signature.getInstance("SHA256withRSA", "SunMSCAPI");
        sig.initSign(privateKey);
        sig.update(data);
        byte[] signature = sig.sign();

        String sigB64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("SIG:" + sigB64);
    }

    private static String getThumbprint(X509Certificate cert) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        byte[] digest = md.digest(der);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}
