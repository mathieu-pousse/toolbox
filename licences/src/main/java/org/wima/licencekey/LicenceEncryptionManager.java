package org.wima.licencekey;

/**
 * This manager handles the ciphering / deciphering.
 *
 * @author Mathieu POUSSE
 */
public interface LicenceEncryptionManager {

    /**
     * Loads the publicKeyFile.
     *
     * @param publicKeyFile the file containing the public key
     * @throws java.security.spec.InvalidKeySpecException in case of invalid key
     * @throws java.io.IOException             if we cannot read the file
     */
    void load(final String publicKeyFile);

    /**
     * Loads the publicKeyFile and privateKeyFile.
     *
     * @param publicKeyFile  the file containing the public key
     * @param privateKeyFile the file containing the private key
     */
    void load(final String publicKeyFile, final String privateKeyFile);

    /**
     * Check the content against the signature.
     *
     * @param content   the signed data
     * @param signature the signature
     * @return true if valid
     */
    boolean verify(final byte[] content, final byte[] signature);

    /**
     * Sign the given input stream data. The signature is append to the output stream.
     *
     * @param data the the data to be signed.
     * @return the signature for the given data.
     */
    byte[] sign(final byte[] data);

}
