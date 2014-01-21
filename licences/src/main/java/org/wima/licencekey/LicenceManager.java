package org.wima.licencekey;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Date;
import java.util.List;

/**
 * This class manages the licence.
 *
 * @author Mathieu POUSSE
 */
public interface LicenceManager {

    /**
     * The licence start marker.
     */
    static final String LICENCE_START = "---------------------- my-application licence - START ----------------------";

    /**
     * The licence end marker.
     */
    static final String LICENCE__END_ = "---------------------- my-application licence -  END  ----------------------";

    public static class ProductLicence implements Serializable {

        private String owner;
        private Date expireAt;
        private List<String> features;

        /**
         * Default constructor.
         */
        public ProductLicence() {
            // void
        }


        /**
         * Sets new owner.
         *
         * @param owner New value of owner.
         */
        public void setOwner(String owner) {
            this.owner = owner;
        }

        /**
         * Gets features.
         *
         * @return Value of features.
         */
        public List<String> getFeatures() {
            return features;
        }

        /**
         * Gets expireAt.
         *
         * @return Value of expireAt.
         */
        public Date getExpireAt() {
            return expireAt;
        }

        /**
         * Gets owner.
         *
         * @return Value of owner.
         */
        public String getOwner() {
            return owner;
        }

        /**
         * Sets new expireAt.
         *
         * @param expireAt New value of expireAt.
         */
        public void setExpireAt(Date expireAt) {
            this.expireAt = expireAt;
        }

        /**
         * Sets new features.
         *
         * @param features New value of features.
         */
        public void setFeatures(List<String> features) {
            this.features = features;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String toString() {
            return "ProductLicence{" +
                    "owner='" + owner + '\'' +
                    ", expireAt=" + expireAt +
                    ", features=" + features +
                    '}';
        }
    }

    /**
     * Loads the licence contained in the specified file name.
     *
     * @param file the file name
     * @return the ready to use licence
     * @throws java.io.IOException               in case of invalid file
     * @throws java.security.InvalidKeyException in case of invalid public key
     * @throws java.security.SignatureException  in case of invalid signature or tampered file
     */
    ProductLicence loadLicence(final String file) throws IOException, InvalidKeyException, SignatureException;

    /**
     * Return a signed version of the product licence.
     *
     * @param toWrite the licence to generate
     * @return return the stringified licence key
     * @throws java.io.IOException               in case of invalid file
     * @throws java.security.InvalidKeyException in case of invalid public key
     * @throws java.security.SignatureException  in case of invalid signature or tampered file
     */
    String saveLicence(final ProductLicence toWrite) throws IOException, InvalidKeyException, SignatureException;

}
