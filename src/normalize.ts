/**
 * Normalization algorithm — converts X.509 Subject DN fields to did:pki path segments.
 * Implements spec §7 (Derivation Algorithm).
 */

const TRANSLITERATION: Record<string, string> = {
  'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u',
  'à': 'a', 'è': 'e', 'ì': 'i', 'ò': 'o', 'ù': 'u',
  'â': 'a', 'ê': 'e', 'î': 'i', 'ô': 'o', 'û': 'u',
  'ä': 'a', 'ë': 'e', 'ï': 'i', 'ö': 'o', 'ü': 'u',
  'ã': 'a', 'õ': 'o',
  'ñ': 'n', 'ç': 'c', 'ß': 'ss',
  'ø': 'o', 'å': 'a', 'æ': 'ae',
};

const CA_PREFIXES = ['ca ', 'ac '];

const COUNTRY_SUFFIXES = [
  'costa rica', 'brasil', 'brazil', 'españa', 'spain',
  'mexico', 'méxico', 'colombia', 'chile', 'argentina',
  'peru', 'perú', 'ecuador', 'uruguay', 'panama', 'panamá',
  'el salvador', 'guatemala', 'honduras', 'nicaragua',
  'united states', 'deutschland', 'germany', 'france', 'italia', 'italy',
];

const SEPARATOR_PATTERNS = [' - ', ' / ', ' – ', ' — '];

/**
 * Known hierarchy level keywords that act as segment boundaries.
 * When these words appear at the start of a cleaned CN followed by a space,
 * they form their own segment. This handles naming conventions like
 * CR's "POLITICA PERSONA FISICA" → ["politica", "persona-fisica"].
 */
const LEVEL_KEYWORDS = ['politica'];

/** Version suffix pattern: " v2", " v10", etc. at end of string */
const VERSION_SUFFIX = /\s+v\d+$/i;

/**
 * Transliterate a UTF-8 string to ASCII.
 */
function transliterate(input: string): string {
  let result = '';
  for (const char of input) {
    const lower = char.toLowerCase();
    result += TRANSLITERATION[lower] ?? (lower.charCodeAt(0) > 127 ? '' : char);
  }
  return result;
}

/**
 * Normalize a certificate Subject CN or O value into did:pki ca-path segments.
 *
 * @param cn - The Common Name field from the X.509 Subject DN
 * @returns Array of normalized path segments (e.g., ['sinpe', 'persona-fisica'])
 */
export function normalizeCN(cn: string): string[] {
  let value = cn;

  // 1. Remove version suffix (e.g., " v2")
  value = value.replace(VERSION_SUFFIX, '');

  // 2. Transliterate to ASCII
  value = transliterate(value);

  // 3. Convert to lowercase
  value = value.toLowerCase();

  // 4. Remove CA prefixes
  for (const prefix of CA_PREFIXES) {
    if (value.startsWith(prefix)) {
      value = value.slice(prefix.length);
      break;
    }
  }

  // 5. Remove country suffixes (with separator)
  for (const country of COUNTRY_SUFFIXES) {
    for (const sep of [' - ', ' de ', ' of ', ' del ']) {
      const suffix = sep + country;
      if (value.endsWith(suffix)) {
        value = value.slice(0, -suffix.length);
        break;
      }
    }
  }

  // 6. Split on hierarchy level keywords (e.g., "politica persona fisica" → "politica" + "persona fisica")
  for (const kw of LEVEL_KEYWORDS) {
    if (value.startsWith(kw + ' ')) {
      value = kw + ' - ' + value.slice(kw.length + 1);
      break;
    }
  }

  // 7. Split on known separators
  let segments: string[] = [value];
  for (const sep of SEPARATOR_PATTERNS) {
    segments = segments.flatMap(s => s.split(sep));
  }

  // 8. Normalize each segment: whitespace → hyphen, clean up
  return segments
    .map(s => s.trim())
    .filter(s => s.length > 0)
    .map(s =>
      s
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .replace(/^-|-$/g, '')
    )
    .filter(s => s.length > 0);
}

/**
 * Derive a did:pki identifier from an X.509 CA certificate's Subject DN.
 *
 * @param countryCode - ISO 3166-1 alpha-2 (from cert's C field)
 * @param cn - Common Name from Subject DN
 * @param org - Organization from Subject DN (optional)
 * @returns The full did:pki string
 */
export function deriveDid(
  countryCode: string,
  cn: string,
  _org?: string,
): string {
  const cc = countryCode.toLowerCase();
  const segments = normalizeCN(cn);
  return `did:pki:${cc}:${segments.join(':')}`;
}

/**
 * Given a Subject CN, derive the ca-path key used for registry lookup.
 *
 * @returns Colon-joined path segments (e.g., "sinpe:persona-fisica")
 */
export function derivePathKey(cn: string): string {
  return normalizeCN(cn).join(':');
}
