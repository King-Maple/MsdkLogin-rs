import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkUtils;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.zip.ZipFile;

/** Run with JDK 17+ and Android's apksig/apksigner JAR; never executes APK code. */
class VerifyApk {
    public static void main(String[] args) throws Exception {
        var result = new ApkVerifier.Builder(new File(args[0])).build().verify();
        if (!result.isVerified()) {
            System.out.println("{\"verified\":false}");
            System.exit(1);
        }
        String packageName;
        try (var zip = new ZipFile(args[0]);
             var stream = zip.getInputStream(zip.getEntry("AndroidManifest.xml"))) {
            byte[] manifest = stream.readNBytes(1048577);
            if (manifest.length > 1048576) throw new IllegalArgumentException("manifest_too_large");
            packageName = ApkUtils.getPackageNameFromBinaryAndroidManifest(ByteBuffer.wrap(manifest));
        }
        if (!packageName.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))
            throw new IllegalArgumentException("unsupported_package_name");
        System.out.printf("{\"verified\":true,\"package_name\":\"%s\",\"v1\":%s,\"v2\":%s,\"v3\":%s,\"warning_count\":%d,\"certificates\":[",
            packageName, result.isVerifiedUsingV1Scheme(), result.isVerifiedUsingV2Scheme(),
            result.isVerifiedUsingV3Scheme(), result.getWarnings().size());
        boolean first = true;
        for (var cert : result.getSignerCertificates()) {
            if (!first) System.out.print(",");
            first = false;
            var md5 = HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(cert.getEncoded()));
            System.out.printf("{\"md5\":\"%s\"}", md5);
        }
        System.out.println("]}");
    }
}
