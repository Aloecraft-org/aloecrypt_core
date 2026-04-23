use super::aloecrypt_api::*;
use super::fixed_byte::*;
use super::galois::*;
use super::reedsolomon::*;
use super::rng::*;
use crate::rng_api::*;

const MAX_VARIANTS: usize = 33;
const MAX_SECRET_LEN: usize = 255;

pub fn to_slip39_secret(data: &[u8]) -> VarU16_255 {
    assert!(
        data.len() % 2 == 0,
        "to_slip39 must be an even number of bytes"
    );
    let mut buf = [0u16; 255];

    let mut data_words = _bytes_to_u16_10bit(data);
    let checksum = create_slip39_rs1024_checksum(&data_words.to_u16_arr());
    let data_len = data_words.value[0];

    data_words.value[(data_len * 2 + 2) as usize..(data_len * 2 + 4) as usize]
        .copy_from_slice(&checksum[0].to_le_bytes());
    data_words.value[(data_len * 2 + 4) as usize..(data_len * 2 + 6) as usize]
        .copy_from_slice(&checksum[1].to_le_bytes());
    data_words.value[(data_len * 2 + 6) as usize..(data_len * 2 + 8) as usize]
        .copy_from_slice(&checksum[2].to_le_bytes());
    data_words.value[0] += 3;
    data_words
}

pub fn from_slip39_secret(data: &[u16]) -> VarByte255 {
    assert!(data.len() >= 3, "Data too short to contain a checksum");
    assert!(
        verify_slip39_rs1024_checksum(data),
        "Invalid RS1024 Checksum"
    );

    let payload = &data[..data.len() - 3];
    let mut value = [0u8; 256];
    let mut bit_buf = 0u32;
    let mut bits_in_buf = 0;
    let mut byte_idx = 1;

    for &word in payload {
        bit_buf = (bit_buf << 10) | (word as u32);
        bits_in_buf += 10;

        while bits_in_buf >= 8 {
            bits_in_buf -= 8;
            value[byte_idx] = (bit_buf >> bits_in_buf) as u8;
            byte_idx += 1;
        }
    }

    value[0] = (byte_idx - 1) as u8;
    VarByte255 { value }
}

pub fn to_slip39_mnemonic(indices: &[u16]) -> VarString511 {
    let mut out = VarString511 { value: EMPTY_B512 };

    let mut out_len = 0;
    for (i, &idx) in indices.iter().enumerate() {
        if i > 0 {
            out.value[out_len + 1] = b' ';
            out_len += 1;
        }
        let word = SLIP39_WORDLIST[idx as usize].as_bytes();
        let w_len = word.len();

        // Copy the word into the buffer
        out.value[out_len + 1..out_len + 1 + w_len].copy_from_slice(word);
        out_len += w_len;
    }
    out.value[0] = out_len as u8;
    out
}

pub fn from_slip39_mnemonic(mnemonic: &VarString511) -> VarU16_255 {
    let mut arr = [0u16; 255];
    let mut len = 0;
    for word in mnemonic.to_str().split(' ') {
        if let Some(idx) = SLIP39_WORDLIST.iter().position(|&w| w == word) {
            arr[len] = idx as u16;
            len += 1;
        }
    }
    VarU16_255::from_u16_arr(&arr[..len])
}

fn _check_nonzero_unique(arr: &[u16]) -> bool {
    for element in arr {
        if *element == 0 {
            return false;
        }

        let mut match_count = 0;
        for other_element in arr {
            if other_element == element {
                match_count += 1
            }
        }
        if match_count > 1 {
            return false;
        }
    }
    return true;
}

macro_rules! impl_create_slip39_shares {
    ($($name:ident, $n:expr);*) => {
        $(
            pub fn $name(secret: VarU16_255, threshold: u8, seed: RngSeed) -> [VarU16_255; $n] {
                let mut coef_buf = [[0u16; MAX_VARIANTS]; MAX_SECRET_LEN];
                let mut secret_buf = [VarU16_255::empty(); $n];
                let mut location_buf = [0u16; $n];
                let mut rng = AloeRng::new(seed);
                while !_check_nonzero_unique(&location_buf) {
                    // Fill the underlying bytes of the u16 array
                    rng._fill_bytes(unsafe {
                        core::slice::from_raw_parts_mut(location_buf.as_mut_ptr() as *mut u8, $n * 2)
                    });
                    // Mask to 10 bits for GF(1024)
                    for loc in location_buf.iter_mut() { *loc &= 0x3FF; }
                }

                for idx in 0..MAX_SECRET_LEN {
                    rng._fill_bytes(unsafe {
                        core::slice::from_raw_parts_mut(coef_buf[idx].as_mut_ptr() as *mut u8, MAX_VARIANTS * 2)
                    });
                    for val in coef_buf[idx].iter_mut() { *val &= 0x3FF; }
                }

                let secret_len = secret.to_u16_arr().len() as u8;
                for i in 0..$n {
                    secret_buf[i].value[0] = secret_len + 1;
                    secret_buf[i].value[2..4].copy_from_slice(&location_buf[i].to_le_bytes());
                }
                _create_n_shares(secret, threshold, rng, coef_buf, &mut secret_buf, &location_buf);
                secret_buf
            }
        )*
    }
}

impl_create_slip39_shares! {
    create_3_slip39_shares, 3;
    create_4_slip39_shares, 4;
    create_5_slip39_shares, 5;
    create_6_slip39_shares, 6;
    create_7_slip39_shares, 7;
    create_8_slip39_shares, 8;
    create_9_slip39_shares, 9;
    create_10_slip39_shares, 10;
    create_11_slip39_shares, 11;
    create_12_slip39_shares, 12;
    create_13_slip39_shares, 13;
    create_14_slip39_shares, 14;
    create_15_slip39_shares, 15;
    create_16_slip39_shares, 16
}

fn _create_n_shares(
    secret: VarU16_255,
    threshold: u8,
    mut rng: AloeRng,
    mut coef_buf: [[u16; MAX_VARIANTS]; MAX_SECRET_LEN],
    secret_buf: &mut [VarU16_255],
    location_buf: &[u16],
) {
    let secret_parts = secret.to_u16_arr();
    let n_shares = secret_buf.len();
    for part_idx in 0..secret_parts.len() {
        for secret_idx in 0..n_shares {
            let x = location_buf[secret_idx];

            let mut y: u16 = if threshold > 1 {
                coef_buf[part_idx][(threshold - 2) as usize]
            } else {
                0
            };
            if threshold > 2 {
                for i in (0..(threshold - 2) as usize).rev() {
                    y = gf1024_add(gf1024_mul(y, x), coef_buf[part_idx][i]);
                }
            }
            y = gf1024_add(gf1024_mul(y, x), secret_parts[part_idx]);
            let offset = 4 + (part_idx * 2);
            secret_buf[secret_idx].value[offset..offset + 2].copy_from_slice(&y.to_le_bytes());
        }
    }
}

pub fn combine_slip39_shares(shares: &[VarU16_255]) -> VarU16_255 {
    let n = shares.len();
    let share_len = shares[0].value[0] as usize;
    let secret_len = share_len - 1;
    let mut result = VarU16_255::empty();
    result.value[0] = secret_len as u8;

    for part_idx in 0..secret_len {
        let mut secret_part = 0u16;
        let offset = 4 + (part_idx * 2);

        for i in 0..n {
            let mut li = 1u16; // The Lagrange basis polynomial evaluated at x=0
            for j in 0..n {
                if i == j {
                    continue;
                }

                let xi = u16::from_le_bytes([shares[i].value[2], shares[i].value[3]]);
                let xj = u16::from_le_bytes([shares[j].value[2], shares[j].value[3]]);

                // Formula for L_i(0): product of (xj / (xj XOR xi))
                let denominator = gf1024_add(xj, xi);
                let fraction = gf1024_mul(xj, gf1024_inv(denominator));
                li = gf1024_mul(li, fraction);
            }

            let yi = u16::from_le_bytes([shares[i].value[offset], shares[i].value[offset + 1]]);
            secret_part = gf1024_add(secret_part, gf1024_mul(yi, li));
        }
        let res_offset = 2 + (part_idx * 2);
        result.value[res_offset..res_offset + 2].copy_from_slice(&secret_part.to_le_bytes());
    }
    result
}

fn _bytes_to_u16_10bit(bytes: &[u8]) -> VarU16_255 {
    let mut acc = [0u16; 252];
    let mut acc_len = 0;
    let mut bits = 0u32;
    let mut bit_count = 0;

    for &b in bytes {
        bits = (bits << 8) | (b as u32);
        bit_count += 8;
        while bit_count >= 10 {
            bit_count -= 10;
            if acc_len < 252 {
                acc[acc_len] = ((bits >> bit_count) & 0x3FF) as u16;
                acc_len += 1;
            }
        }
    }

    if bit_count > 0 && acc_len < 252 {
        acc[acc_len] = ((bits << (10 - bit_count)) & 0x3FF) as u16;
        acc_len += 1;
    }

    let mut out = VarU16_255::from_u16_arr(&acc);
    out.value[0] = acc_len as u8;
    out
}

#[cfg(feature = "slip39_words")]
pub const SLIP39_WORDLIST: [&str; 1024] = [
    "academic", "acid", "acne", "acquire", "acrobat", "activity", "actress", "adapt", "adequate",
    "adjust", "admit", "adorn", "adult", "advance", "advocate", "afraid", "again", "agency",
    "agree", "aide", "aircraft", "airline", "airport", "ajar", "alarm", "album", "alcohol",
    "alien", "alive", "alpha", "already", "alto", "aluminum", "always", "amazing", "ambition",
    "amount", "amuse", "analysis", "anatomy", "ancestor", "ancient", "angel", "angry", "animal",
    "answer", "antenna", "anxiety", "apart", "aquatic", "arcade", "arena", "argue", "armed",
    "artist", "artwork", "aspect", "auction", "august", "aunt", "average", "aviation", "avoid",
    "award", "away", "axis", "axle", "beam", "beard", "beaver", "become", "bedroom", "behavior",
    "being", "believe", "belong", "benefit", "best", "beyond", "bike", "biology", "birthday",
    "bishop", "black", "blanket", "blessing", "blimp", "blind", "blue", "body", "bolt", "boring",
    "born", "both", "boundary", "bracelet", "branch", "brave", "breathe", "briefing", "broken",
    "brother", "browser", "bucket", "budget", "building", "bulb", "bulge", "bumpy", "bundle",
    "burden", "burning", "busy", "buyer", "cage", "calcium", "camera", "campus", "canyon",
    "capacity", "capital", "capture", "carbon", "cards", "careful", "cargo", "carpet", "carve",
    "category", "cause", "ceiling", "center", "ceramic", "champion", "change", "charity", "check",
    "chemical", "chest", "chew", "chubby", "cinema", "civil", "class", "clay", "cleanup", "client",
    "climate", "clinic", "clock", "clogs", "closet", "clothes", "club", "cluster", "coal",
    "coastal", "coding", "column", "company", "corner", "costume", "counter", "course", "cover",
    "cowboy", "cradle", "craft", "crazy", "credit", "cricket", "criminal", "crisis", "critical",
    "crowd", "crucial", "crunch", "crush", "crystal", "cubic", "cultural", "curious", "curly",
    "custody", "cylinder", "daisy", "damage", "dance", "darkness", "database", "daughter",
    "deadline", "deal", "debris", "debut", "decent", "decision", "declare", "decorate", "decrease",
    "deliver", "demand", "density", "deny", "depart", "depend", "depict", "deploy", "describe",
    "desert", "desire", "desktop", "destroy", "detailed", "detect", "device", "devote", "diagnose",
    "dictate", "diet", "dilemma", "diminish", "dining", "diploma", "disaster", "discuss",
    "disease", "dish", "dismiss", "display", "distance", "dive", "divorce", "document", "domain",
    "domestic", "dominant", "dough", "downtown", "dragon", "dramatic", "dream", "dress", "drift",
    "drink", "drove", "drug", "dryer", "duckling", "duke", "duration", "dwarf", "dynamic", "early",
    "earth", "easel", "easy", "echo", "eclipse", "ecology", "edge", "editor", "educate", "either",
    "elbow", "elder", "election", "elegant", "element", "elephant", "elevator", "elite", "else",
    "email", "emerald", "emission", "emperor", "emphasis", "employer", "empty", "ending",
    "endless", "endorse", "enemy", "energy", "enforce", "engage", "enjoy", "enlarge", "entrance",
    "envelope", "envy", "epidemic", "episode", "equation", "equip", "eraser", "erode", "escape",
    "estate", "estimate", "evaluate", "evening", "evidence", "evil", "evoke", "exact", "example",
    "exceed", "exchange", "exclude", "excuse", "execute", "exercise", "exhaust", "exotic",
    "expand", "expect", "explain", "express", "extend", "extra", "eyebrow", "facility", "fact",
    "failure", "faint", "fake", "false", "family", "famous", "fancy", "fangs", "fantasy", "fatal",
    "fatigue", "favorite", "fawn", "fiber", "fiction", "filter", "finance", "findings", "finger",
    "firefly", "firm", "fiscal", "fishing", "fitness", "flame", "flash", "flavor", "flea",
    "flexible", "flip", "float", "floral", "fluff", "focus", "forbid", "force", "forecast",
    "forget", "formal", "fortune", "forward", "founder", "fraction", "fragment", "frequent",
    "freshman", "friar", "fridge", "friendly", "frost", "froth", "frozen", "fumes", "funding",
    "furl", "fused", "galaxy", "game", "garbage", "garden", "garlic", "gasoline", "gather",
    "general", "genius", "genre", "genuine", "geology", "gesture", "glad", "glance", "glasses",
    "glen", "glimpse", "goat", "golden", "graduate", "grant", "grasp", "gravity", "gray",
    "greatest", "grief", "grill", "grin", "grocery", "gross", "group", "grownup", "grumpy",
    "guard", "guest", "guilt", "guitar", "gums", "hairy", "hamster", "hand", "hanger", "harvest",
    "have", "havoc", "hawk", "hazard", "headset", "health", "hearing", "heat", "helpful", "herald",
    "herd", "hesitate", "hobo", "holiday", "holy", "home", "hormone", "hospital", "hour", "huge",
    "human", "humidity", "hunting", "husband", "hush", "husky", "hybrid", "idea", "identify",
    "idle", "image", "impact", "imply", "improve", "impulse", "include", "income", "increase",
    "index", "indicate", "industry", "infant", "inform", "inherit", "injury", "inmate", "insect",
    "inside", "install", "intend", "intimate", "invasion", "involve", "iris", "island", "isolate",
    "item", "ivory", "jacket", "jerky", "jewelry", "join", "judicial", "juice", "jump", "junction",
    "junior", "junk", "jury", "justice", "kernel", "keyboard", "kidney", "kind", "kitchen",
    "knife", "knit", "laden", "ladle", "ladybug", "lair", "lamp", "language", "large", "laser",
    "laundry", "lawsuit", "leader", "leaf", "learn", "leaves", "lecture", "legal", "legend",
    "legs", "lend", "length", "level", "liberty", "library", "license", "lift", "likely", "lilac",
    "lily", "lips", "liquid", "listen", "literary", "living", "lizard", "loan", "lobe", "location",
    "losing", "loud", "loyalty", "luck", "lunar", "lunch", "lungs", "luxury", "lying", "lyrics",
    "machine", "magazine", "maiden", "mailman", "main", "makeup", "making", "mama", "manager",
    "mandate", "mansion", "manual", "marathon", "march", "market", "marvel", "mason", "material",
    "math", "maximum", "mayor", "meaning", "medal", "medical", "member", "memory", "mental",
    "merchant", "merit", "method", "metric", "midst", "mild", "military", "mineral", "minister",
    "miracle", "mixed", "mixture", "mobile", "modern", "modify", "moisture", "moment", "morning",
    "mortgage", "mother", "mountain", "mouse", "move", "much", "mule", "multiple", "muscle",
    "museum", "music", "mustang", "nail", "national", "necklace", "negative", "nervous", "network",
    "news", "nuclear", "numb", "numerous", "nylon", "oasis", "obesity", "object", "observe",
    "obtain", "ocean", "often", "olympic", "omit", "oral", "orange", "orbit", "order", "ordinary",
    "organize", "ounce", "oven", "overall", "owner", "paces", "pacific", "package", "paid",
    "painting", "pajamas", "pancake", "pants", "papa", "paper", "parcel", "parking", "party",
    "patent", "patrol", "payment", "payroll", "peaceful", "peanut", "peasant", "pecan", "penalty",
    "pencil", "percent", "perfect", "permit", "petition", "phantom", "pharmacy", "photo", "phrase",
    "physics", "pickup", "picture", "piece", "pile", "pink", "pipeline", "pistol", "pitch",
    "plains", "plan", "plastic", "platform", "playoff", "pleasure", "plot", "plunge", "practice",
    "prayer", "preach", "predator", "pregnant", "premium", "prepare", "presence", "prevent",
    "priest", "primary", "priority", "prisoner", "privacy", "prize", "problem", "process",
    "profile", "program", "promise", "prospect", "provide", "prune", "public", "pulse", "pumps",
    "punish", "puny", "pupal", "purchase", "purple", "python", "quantity", "quarter", "quick",
    "quiet", "race", "racism", "radar", "railroad", "rainbow", "raisin", "random", "ranked",
    "rapids", "raspy", "reaction", "realize", "rebound", "rebuild", "recall", "receiver",
    "recover", "regret", "regular", "reject", "relate", "remember", "remind", "remove", "render",
    "repair", "repeat", "replace", "require", "rescue", "research", "resident", "response",
    "result", "retailer", "retreat", "reunion", "revenue", "review", "reward", "rhyme", "rhythm",
    "rich", "rival", "river", "robin", "rocky", "romantic", "romp", "roster", "round", "royal",
    "ruin", "ruler", "rumor", "sack", "safari", "salary", "salon", "salt", "satisfy", "satoshi",
    "saver", "says", "scandal", "scared", "scatter", "scene", "scholar", "science", "scout",
    "scramble", "screw", "script", "scroll", "seafood", "season", "secret", "security", "segment",
    "senior", "shadow", "shaft", "shame", "shaped", "sharp", "shelter", "sheriff", "short",
    "should", "shrimp", "sidewalk", "silent", "silver", "similar", "simple", "single", "sister",
    "skin", "skunk", "slap", "slavery", "sled", "slice", "slim", "slow", "slush", "smart", "smear",
    "smell", "smirk", "smith", "smoking", "smug", "snake", "snapshot", "sniff", "society",
    "software", "soldier", "solution", "soul", "source", "space", "spark", "speak", "species",
    "spelling", "spend", "spew", "spider", "spill", "spine", "spirit", "spit", "spray", "sprinkle",
    "square", "squeeze", "stadium", "staff", "standard", "starting", "station", "stay", "steady",
    "step", "stick", "stilt", "story", "strategy", "strike", "style", "subject", "submit", "sugar",
    "suitable", "sunlight", "superior", "surface", "surprise", "survive", "sweater", "swimming",
    "swing", "switch", "symbolic", "sympathy", "syndrome", "system", "tackle", "tactics",
    "tadpole", "talent", "task", "taste", "taught", "taxi", "teacher", "teammate", "teaspoon",
    "temple", "tenant", "tendency", "tension", "terminal", "testify", "texture", "thank", "that",
    "theater", "theory", "therapy", "thorn", "threaten", "thumb", "thunder", "ticket", "tidy",
    "timber", "timely", "ting", "tofu", "together", "tolerate", "total", "toxic", "tracks",
    "traffic", "training", "transfer", "trash", "traveler", "treat", "trend", "trial", "tricycle",
    "trip", "triumph", "trouble", "true", "trust", "twice", "twin", "type", "typical", "ugly",
    "ultimate", "umbrella", "uncover", "undergo", "unfair", "unfold", "unhappy", "union",
    "universe", "unkind", "unknown", "unusual", "unwrap", "upgrade", "upstairs", "username",
    "usher", "usual", "valid", "valuable", "vampire", "vanish", "various", "vegan", "velvet",
    "venture", "verdict", "verify", "very", "veteran", "vexed", "victim", "video", "view",
    "vintage", "violence", "viral", "visitor", "visual", "vitamins", "vocal", "voice", "volume",
    "voter", "voting", "walnut", "warmth", "warn", "watch", "wavy", "wealthy", "weapon", "webcam",
    "welcome", "welfare", "western", "width", "wildlife", "window", "wine", "wireless", "wisdom",
    "withdraw", "wits", "wolf", "woman", "work", "worthy", "wrap", "wrist", "writing", "wrote",
    "year", "yelp", "yield", "yoga", "zero",
];
