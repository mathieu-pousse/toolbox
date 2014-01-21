package org.wima.licencekey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * This class handles the licence ciphering / deciphering.
 * <p/>
 * <p/>
 * <pre>
 * Generate your keys
 * ==================
 *
 * Create the private key (containing information to create the public key).
 *
 *   $ openssl genrsa -out private-key.pem 2048
 *   $ openssl pkcs8 -topk8 -in private-key.pem -inform PEM -nocrypt -outform DER -out private-key.der
 *
 * Extract the public key, fur publishing.
 *   $ openssl rsa -in private-key.pem -out public-key.der -pubout -outform DER
 * </pre>
 *
 * @author Mathieu POUSSE
 */
public class LicenceEncryptionManagerImpl implements LicenceEncryptionManager {

    /**
     * The public key shipped with the application.
     */
    private PublicKey publicKey;

    /**
     * Our private key, only available internally.
     */
    private PrivateKey privateKey;

    /**
     * Flush the input stream to a byte array.
     *
     * @param is the input
     * @return see description
     * @throws IOException in case of...
     */
    public static byte[] toByteArray(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[2048];
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        try {
            is.close();
        } catch (IOException io) {
            // hum...
        }
        buffer.flush();
        return buffer.toByteArray();
    }

    /**
     * Create a key factory instance with the specified algorithm.
     *
     * @param algorithm the algorithm
     * @return the key factory
     */
    private KeyFactory safeGetKeyFactory(final String algorithm) {
        try {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(algorithm + " implementation is missing");
        }
    }

    /**
     * Create a signature instance with the specified algorithm.
     *
     * @param algorithm the algoritm
     * @return the signature
     */
    private Signature safeGetSignature(final String algorithm) {
        try {
            return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(algorithm + " implementation is missing");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void load(final String publicKeyFile) {
        try {
            load(toByteArray(LicenceManagerImpl.class.getResourceAsStream(publicKeyFile)));
        } catch (IOException e) {
            throw new SecurityException("invalid public key", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void load(final String publicKeyFile, final String privateKeyFile) {
        try {
            Class<LicenceEncryptionManager> loader = LicenceEncryptionManager.class;
            InputStream publicKeyIS = publicKeyFile == null ? null : loader.getResourceAsStream(publicKeyFile);
            InputStream privateKeyIS = privateKeyFile == null ? null : loader.getResourceAsStream(privateKeyFile);

            if (privateKeyFile == null) {
                // we are probably running in a production mode
                load(toByteArray(publicKeyIS));
            } else {
                // we've got it, we load it !
                load(toByteArray(publicKeyIS), toByteArray(privateKeyIS));
            }
        } catch (IOException e) {
            throw new SecurityException("invalid keys", e);
        }

    }

    /**
     * Load the publicKey.
     *
     * @param publicKey the public key bytes
     * @throws java.security.spec.InvalidKeySpecException
     */
    protected void load(final byte[] publicKey) {
        load(publicKey, null);
    }

    /**
     * Loads the public and private key if available.
     *
     * @param publicKey  the public key (can't be null).
     * @param privateKey the private key (null if not available).
     */
    protected void load(final byte[] publicKey, final byte[] privateKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
            this.publicKey = safeGetKeyFactory("RSA").generatePublic(spec);

            if (privateKey != null) {
                PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKey);
                this.privateKey = safeGetKeyFactory("RSA").generatePrivate(privateSpec);
            }
        } catch (InvalidKeySpecException e) {
            throw new SecurityException("invalid keys", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(final byte[] content, final byte[] signature) {
        try {
            // Initialize the signing algorithm with our public key
            Signature rsaSignature = safeGetSignature("SHA1withRSA");
            rsaSignature.initVerify(this.publicKey);

            // Update the signature algorithm with the data.
            rsaSignature.update(content);

            // Validate the signature
            return rsaSignature.verify(signature);
        } catch (InvalidKeyException | SignatureException e) {
            // something went wrong...
            return false;
        }

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] sign(final byte[] data) {
        if (this.privateKey == null) {
            throw new IllegalArgumentException("cannot sign the licence (private-key is missing)");
        }

        try {
            // Initialize the signing algorithm with our private key
            Signature rsaSignature = safeGetSignature("SHA1withRSA");
            rsaSignature.initSign(this.privateKey);
            rsaSignature.update(data);

            // Generate the signature.
            return rsaSignature.sign();
        } catch (SignatureException | InvalidKeyException e) {
            throw new SecurityException(e);
        }
    }

}
