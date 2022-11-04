package cat.uvic.teknos.m09.matias.cryptoutils.exceptions;

public class CryptoUtilsExceptions extends RuntimeException{
    public CryptoUtilsExceptions() {
    }

    public CryptoUtilsExceptions(String message) {
        super(message);
    }

    public CryptoUtilsExceptions(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoUtilsExceptions(Throwable cause) {
        super(cause);
    }

    public CryptoUtilsExceptions(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
