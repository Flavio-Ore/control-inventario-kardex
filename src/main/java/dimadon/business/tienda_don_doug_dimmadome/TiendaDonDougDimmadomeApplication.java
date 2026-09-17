package dimadon.business.tienda_don_doug_dimmadome;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TiendaDonDougDimmadomeApplication {

	private static final List<String> CONFIG_KEYS = List.of(
			"DB_URL",
			"DB_USERNAME",
			"DB_PASSWORD",
			"RENIEC_API_URL",
			"RENIEC_API_TOKEN");

	public static void main(String[] args) {
		loadConfiguration();
		SpringApplication.run(TiendaDonDougDimmadomeApplication.class, args);
	}

	private static void loadConfiguration() {
		Properties dotEnvProperties = loadDotEnv();

		for (String key : CONFIG_KEYS) {
			String value = resolveConfigValue(key, dotEnvProperties);
			if (value != null && !value.isBlank()) {
				System.setProperty(key, value);
			}
		}
	}

	private static String resolveConfigValue(String key, Properties dotEnvProperties) {
		String value = System.getProperty(key);
		if (value == null || value.isBlank()) {
			value = System.getenv(key);
		}

		if ((value == null || value.isBlank()) && dotEnvProperties != null) {
			value = dotEnvProperties.getProperty(key);
		}

		return value;
	}

	private static Properties loadDotEnv() {
		Path dotEnvPath = Path.of(".env");
		if (!Files.exists(dotEnvPath)) {
			return new Properties();
		}

		Properties properties = new Properties();
		try (InputStream inputStream = Files.newInputStream(dotEnvPath)) {
			properties.load(inputStream);
			return properties;
		} catch (IOException exception) {
			throw new IllegalStateException("No se pudo leer el archivo .env", exception);
		}

	}

}
