package org.wima.licencekey;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class can read and write the licence files.
 *
 * @author Mathieu POUSSE
 */
public class LicenceManagerImpl implements LicenceManager {

    private static final Pattern LICENCE_START_PATTERN = Pattern.compile(LICENCE_START);

    private static final Pattern LICENCE__END__PATTERN = Pattern.compile(LICENCE__END_);

    @Resource
    private LicenceEncryptionManager encryptionManager;

    /**
     * This is triggered when the application is loaded. It will try load the public / private keys if any.
     *
     * @throws java.security.spec.InvalidKeySpecException in case of...
     * @throws java.io.IOException                        in case of...
     */
    @PostConstruct
    public void initialize() {
        if (this.encryptionManager == null) {
            // we are not running with spring
            this.encryptionManager = new LicenceEncryptionManagerImpl();
        }
        this.encryptionManager.load("/public-key.der", "/private-key.der");
    }

    /**
     * Apply the specified XOR on the table.
     *
     * @param table  the table to XORify
     * @param offset the offest
     */
    private void xor(final byte[] table, final byte offset) {
        for (int i = 0; i < table.length; i++) {
            table[i] ^= offset;
        }
    }


    /**
     * Load a licence file and return it.
     *
     * @param licenceFile the file containing the licence.
     * @return the licence information
     * @throws java.io.IOException                    if we cannot read the file
     * @throws java.security.InvalidKeyException      if the licence was tampered
     * @throws java.security.SignatureException       in case of...
     * @throws java.security.NoSuchAlgorithmException in case of...
     */
    public ProductLicence loadLicence(final File licenceFile) {
        try {
            byte[] buffer = LicenceEncryptionManagerImpl.toByteArray(new FileInputStream(licenceFile));
            return loadLicence(new String(buffer, "UTF-8"));
        } catch (IOException e) {
            throw new SecurityException("licence error", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ProductLicence loadLicence(final String stringified) {
        try {
            List<String> content = new ArrayList<>();
            BufferedReader reader = new BufferedReader(new StringReader(stringified));
            String l = null;
            while ((l = reader.readLine()) != null) {
                content.add(l);
            }
            StringBuilder base64Content = new StringBuilder();
            boolean hasStarted = false;
            for (final String line : content) {
                if (!hasStarted && LICENCE_START_PATTERN.matcher(line).find()) {
                    hasStarted = true;
                    continue;
                }
                if (hasStarted) {
                    if (LICENCE__END__PATTERN.matcher(line).find()) {
                        break;
                    }
                    base64Content.append(line);
                }
            }

            byte[] serialized = DatatypeConverter.parseBase64Binary(base64Content.toString());
            xor(serialized, (byte) 38);

            int signatureLength = 0;
            byte[] signature;
            byte[] licence;

            ObjectInputStream deserializer = new ObjectInputStream(new ByteArrayInputStream(serialized));
            try {
                signatureLength = deserializer.readInt();
                signature = new byte[signatureLength];
                deserializer.read(signature);
                licence = new byte[deserializer.available()];
                deserializer.read(licence);

            } finally {
                deserializer.close();
            }

            if (!this.encryptionManager.verify(licence, signature)) {
                // invalid licence
                return null;
            }

            try {
                deserializer = new ObjectInputStream(new ByteArrayInputStream(licence));
                return (ProductLicence) deserializer.readObject();
            } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException("hum...");
            } finally {
                deserializer.close();
            }

        } catch (IOException e) {
            throw new SecurityException("licence error", e);
        }

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String saveLicence(final ProductLicence toWrite) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream serializer = new ObjectOutputStream(baos);
            serializer.writeObject(toWrite);
            serializer.close();
            byte[] licence = baos.toByteArray();
            byte[] signature = this.encryptionManager.sign(licence);

            baos = new ByteArrayOutputStream();
            serializer = new ObjectOutputStream(baos);

            serializer.writeInt(signature.length);
            serializer.write(signature);
            serializer.write(licence);
            serializer.close();

            licence = baos.toByteArray();
            xor(licence, (byte) 38);


            String encoded = DatatypeConverter.printBase64Binary((licence));
            Matcher lines = Pattern.compile(".{1," + LICENCE_START.length() + "}").matcher(encoded);

            StringBuilder builder = new StringBuilder();
            // output the licence
            builder.append(LICENCE_START).append("\n");
            while (lines.find()) {
                builder.append(lines.group()).append("\n");
            }
            builder.append(LICENCE__END_).append("\n").append("\n");

            return builder.toString();
        } catch (Exception e) {
            throw new SecurityException("licence error", e);
        }
    }

    /**
     * Example !
     *
     * @param args nothing
     */
    public static void main(String... args) {
        String licence = "void";
        // server side
        {
            // let's create a new product licence !
            ProductLicence productLicence = new ProductLicence();
            productLicence.setOwner("Mathieu POUSSE");
            productLicence.setExpireAt(new Date());
            productLicence.setFeatures(Arrays.asList("the", "wonderful", "features", "are", "enabled"));

            System.out.println("original licence : " + productLicence.toString());
            // create manually the managers, but that should be done by CDI
            LicenceManagerImpl licenceManager = new LicenceManagerImpl();
            licenceManager.encryptionManager = new LicenceEncryptionManagerImpl();
            // load both keys
            licenceManager.encryptionManager.load("/public-key.der", "/private-key.der");
            licence = licenceManager.saveLicence(productLicence);
            System.out.println(licence);
        }

        // client side
        {
            // create manually the managers, but that should be done by CDI
            LicenceManagerImpl licenceManager = new LicenceManagerImpl();
            licenceManager.encryptionManager = new LicenceEncryptionManagerImpl();
            // only load the public key to check the signature
            licenceManager.encryptionManager.load("/public-key.der", null);
            ProductLicence reloaded = licenceManager.loadLicence(licence);
            System.out.println("reloaded licence : " + reloaded.toString());
        }
    }

}
