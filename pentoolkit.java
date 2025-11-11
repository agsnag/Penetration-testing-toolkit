import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.Base64;

public class Pentoolkit {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String cmd = args[0];

        Map<String, String> flags = parseFlags(Arrays.copyOfRange(args, 1, args.length));
        List<String> pos = parsePositionals(Arrays.copyOfRange(args, 1, args.length));

        if ("scan".equalsIgnoreCase(cmd)) {
            if (pos.size() < 1) { System.out.println("Error: host missing"); printUsage(); return; }
            String host = pos.get(0);
            int start = Integer.parseInt(flags.getOrDefault("start", "1"));
            int end = Integer.parseInt(flags.getOrDefault("end", "1024"));
            int threads = Integer.parseInt(flags.getOrDefault("threads", "100"));
            portScan(host, start, end, threads);
        } else if ("brute".equalsIgnoreCase(cmd)) {
            if (pos.size() < 2) { System.out.println("Error: url or username missing"); printUsage(); return; }
            String url = pos.get(0);
            String username = pos.get(1);
            String passfile = flags.get("passfile");
            boolean basic = flags.containsKey("basic");
            int threads = Integer.parseInt(flags.getOrDefault("threads", "10"));

            if (passfile == null) { System.out.println("Error: --passfile required"); printUsage(); return; }
            bruteForce(url, username, passfile, basic, threads);
        } else {
            System.out.println("Unknown command: " + cmd);
            printUsage();
        }
    }

    // -------------------------
    // Port scanner
    // -------------------------
    static void portScan(String host, int start, int end, int threads) {
        System.out.printf("Scanning %s ports %d-%d with %d threads%n", host, start, end, threads);
        ExecutorService ex = Executors.newFixedThreadPool(threads);
        List<Future<Integer>> futures = new ArrayList<>();

        for (int p = start; p <= end; p++) {
            final int port = p;
            futures.add(ex.submit(() -> {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(host, port), 300);
                    return port;
                } catch (IOException e) {
                    return -1;
                }
            }));
        }

        ex.shutdown();

        for (Future<Integer> f : futures) {
            try {
                int res = f.get();
                if (res != -1) System.out.println("[OPEN] Port " + res);
            } catch (Exception ignored) {}
        }
        System.out.println("Scan finished.");
    }

    // -------------------------
    // Brute forcer
    // -------------------------
    static void bruteForce(String urlStr, String username, String passfile, boolean basic, int threads) {
        System.out.printf("Brute forcing %s as %s using %s (basic=%b) with %d threads%n",
                urlStr, username, passfile, basic, threads);

        List<String> passwords;
        try {
            passwords = Files.readAllLines(Paths.get(passfile));
        } catch (IOException e) {
            System.out.println("Cannot read passfile: " + e.getMessage());
            return;
        }

        ExecutorService ex = Executors.newFixedThreadPool(threads);
        for (String pw : passwords) {
            final String pass = pw.trim();
            if (pass.isEmpty()) continue;

            ex.submit(() -> {
                try {
                    if (basic) {
                        if (tryBasicAuth(urlStr, username, pass)) {
                            System.out.println("[SUCCESS] " + username + ":" + pass);
                            ex.shutdownNow();
                        }
                    } else {
                        if (tryFormAuth(urlStr, username, pass)) {
                            System.out.println("[SUCCESS] " + username + ":" + pass);
                            ex.shutdownNow();
                        }
                    }
                } catch (Exception ignored) {}
            });
        }

        ex.shutdown();
        try { ex.awaitTermination(1, TimeUnit.HOURS); } catch (InterruptedException ignored) {}
        System.out.println("Brute finished.");
    }

    static boolean tryBasicAuth(String urlStr, String user, String pass) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        String auth = user + ":" + pass;
        String encoded = Base64.getEncoder().encodeToString(auth.getBytes("UTF-8"));
        conn.setRequestProperty("Authorization", "Basic " + encoded);
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        conn.setInstanceFollowRedirects(false);
        int code = conn.getResponseCode();
        // treat 200 as success; 401/403 as failure
        return code == 200;
    }

    static boolean tryFormAuth(String urlStr, String user, String pass) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        String body = "username=" + URLEncoder.encode(user, "UTF-8")
                + "&password=" + URLEncoder.encode(pass, "UTF-8");
        conn.setFixedLengthStreamingMode(body.getBytes().length);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes());
            os.flush();
        }

        int code = conn.getResponseCode();
        // Heuristic: success if not 401/403 and response length > 0 and not redirect to login
        if (code == 200) {
            String resp = readStream(conn.getInputStream());
            // naive check: many login pages contain 'invalid' on failure
            if (!resp.toLowerCase().contains("invalid") && !resp.toLowerCase().contains("login")) {
                return true;
            }
        }
        return false;
    }

    static String readStream(InputStream in) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line).append('\n');
        return sb.toString();
    }

    // -------------------------
    // Simple CLI helpers
    // -------------------------
    static Map<String, String> parseFlags(String[] args) {
        Map<String, String> out = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                String key = a.substring(2);
                // flag without value (boolean) handled by presence
                if (i + 1 < args.length && !args[i+1].startsWith("--")) {
                    out.put(key, args[i+1]);
                    i++;
                } else {
                    out.put(key, "true");
                }
            }
        }
        return out;
    }

    static List<String> parsePositionals(String[] args) {
        List<String> pos = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--")) {
                // If previous was a flag that consumed this value, skip it
                if (i > 0 && args[i-1].startsWith("--") && (i < args.length && !args[i].startsWith("--"))) {
                    // but we cannot be sure; simple heuristic: if previous flag exists and next isn't a flag, it was flag value
                    // To keep simple, we only include args that are not flag keys or flag values by scanning keys:
                    // We'll skip this complexity here; simpler: collect tokens that are not part of "--key value"
                }
            }
        }
        // Simple positional collector: iterate and skip flagged values
        Set<Integer> skip = new HashSet<>();
        for (int i=0;i<args.length;i++){
            if (args[i].startsWith("--")) {
                if (i+1 < args.length && !args[i+1].startsWith("--")) skip.add(i+1);
                continue;
            }
        }
        for (int i=0;i<args.length;i++) {
            if (!args[i].startsWith("--") && !skip.contains(i)) pos.add(args[i]);
        }
        return pos;
    }

    static void printUsage() {
        System.out.println("Pentoolkit (simple)");
        System.out.println("Commands:");
        System.out.println("  scan <host> --start <n> --end <m> [--threads <t>]");
        System.out.println("    Example: java Pentoolkit scan 192.168.1.10 --start 1 --end 1024 --threads 200");
        System.out.println();
        System.out.println("  brute <url> <username> --passfile <file> [--basic] [--threads <t>]");
        System.out.println("    Example (basic auth): java Pentoolkit brute http://example.com/protected admin --passfile wordlist.txt --basic");
        System.out.println("    Example (form): java Pentoolkit brute http://example.com/login admin --passfile wordlist.txt");
        System.out.println();
        System.out.println("LEGAL: Only test with permission.");
    }
}
