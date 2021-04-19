package AuthUtils;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateReader {
    public static X509Certificate getInstance(String filename) throws FileNotFoundException, CertificateException {
        InputStream inputStream = new FileInputStream(filename);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        return certificate;
    }

    public static X509Certificate getInstance(byte[] bytes) throws Exception{
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(bytes);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        return certificate;
    }
}
