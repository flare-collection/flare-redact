// Model-free entity recognition: the job a PII token-classification model does
// (openai/privacy-filter, GLiNER-PII and similar), done with cues, shapes,
// word lists and a score instead of weights.
//
// A model is good at text with no fixed format: a name in a sentence, an
// address over two lines, a birth date as opposed to any other date, a
// customer number that only means something because of the words before it.
// Regex detectors miss all of these. This module scores each candidate on the
// same evidence a model learns to use:
//
//   - a cue before it ("my name is", "lives at", "DOB", "account no."), in the
//     library's 24 languages
//   - its shape (capitalised tokens, house number + street type, postcode)
//   - the word lists in entity-lexicon.ts (given names, surnames, non-persons)
//   - context around it (person words nearby, "order"/"invoice" nearby)
//   - consistency: once "Alice Johnson" is a person, a later "Alice" is too
//
// The labels follow openai/privacy-filter where they overlap, so the output can
// stand in for that model: private_person, private_address, private_phone,
// private_date, account_number, private_url, secret, plus private_handle.
// Email addresses stay with the core `email` detector.
//
// Everything is synchronous, deterministic and linear in the input: every
// pattern has bounded repetition, and each pass is one scan of the text.

import type { Detector } from './detectors.js';
import type { Risk, SemanticFinding, SemanticProvider } from './engine.js';
import { AMBIGUOUS_NAMES, GIVEN_NAMES, NON_PERSON, SURNAMES } from './entity-lexicon.js';

export const ENTITY_LABELS = [
  'private_person',
  'private_address',
  'private_phone',
  'private_date',
  'account_number',
  'private_handle',
  'private_url',
  'secret',
] as const;

export type EntityLabel = (typeof ENTITY_LABELS)[number];

export interface EntityOptions {
  /** Labels to emit (default: all of ENTITY_LABELS). */
  labels?: readonly EntityLabel[];
  /** Drop entities scored below this, from 0 to 1 (default: 0.5). */
  minConfidence?: number;
  /** Also mark later mentions of a recognised person's name (default: true). */
  propagate?: boolean;
}

export interface EntityFinding extends SemanticFinding {
  detector: EntityLabel;
  risk: Risk;
  confidence: number;
}

const NEVER = /(?!)/;

function entityDetector(id: EntityLabel, label: string, why: string, mask: string, risk: Risk = 'high', priority?: number): Detector {
  const det: Detector = { id, label, why, pattern: NEVER, mask: () => mask, default: false, tags: ['entities'], risk, confidence: 0.8 };
  if (priority !== undefined) det.priority = priority;
  return det;
}

/**
 * Registry entries, so `enable: ['entities']`, `disable: ['private_url']`,
 * `--list` and the masks work like any other detector. Their pattern never
 * matches; the engine hands them to recognizeEntities() instead.
 */
export const ENTITY_DETECTORS: Detector[] = [
  // Priority 75 lets these win over the older label-only person_name (60),
  // street_address (65) and date_of_birth (70) detectors on the same text.
  entityDetector('private_person', 'Person (recognised)', 'A person named in free text, found from cues, name lists and context.', '[REDACTED PERSON]', 'high', 75),
  entityDetector('private_address', 'Postal address (recognised)', 'A street address, PO box or postcode line written in free text.', '[REDACTED ADDRESS]', 'high', 75),
  entityDetector('private_phone', 'Phone number (recognised)', 'A phone number identified by a nearby cue or an international prefix.', '[REDACTED PHONE]'),
  entityDetector('private_date', 'Personal date (recognised)', 'A birth date or another date tied to a person (admission, death, appointment).', '[REDACTED DATE]', 'high', 75),
  entityDetector('account_number', 'Account or ID number (recognised)', 'A customer, policy, passport, patient or other ID that only a nearby label identifies.', '[REDACTED ACCOUNT]'),
  entityDetector('private_handle', 'Username or handle (recognised)', 'A social handle or login name that points at one person.', '[REDACTED HANDLE]'),
  entityDetector('private_url', 'Personal URL (recognised)', 'A profile link, or a URL whose query carries personal data.', '[REDACTED URL]'),
  entityDetector('secret', 'Secret in prose (recognised)', 'A password, PIN or one-time code given in a sentence rather than a key=value pair.', '[REDACTED SECRET]', 'critical'),
];

const ENTITY_SET: ReadonlySet<Detector> = new Set(ENTITY_DETECTORS);
const RISK = new Map<string, Risk>(ENTITY_DETECTORS.map((d) => [d.id, d.risk!]));

export const isEntityDetector = (det: Detector): boolean => ENTITY_SET.has(det);

// ---------------------------------------------------------------------------
// Pattern building blocks
// ---------------------------------------------------------------------------

const SP = '[ \\t\\u00A0]';
// Unicode-mode patterns reject needless escapes such as \-, so only syntax characters are escaped.
const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** Case-insensitive source for a cue phrase, leaving the rest of the pattern case-sensitive. */
function ci(phrase: string): string {
  let out = '';
  for (const ch of phrase) {
    if (ch === ' ') out += `${SP}+`;
    else if (ch === "'") out += "['\\u2019]";
    else {
      const lo = ch.toLowerCase();
      const up = ch.toUpperCase();
      out += lo !== up && lo.length === 1 && up.length === 1 ? `[${esc(lo)}${esc(up)}]` : esc(ch);
    }
  }
  return out;
}

/** Longest phrase first, so "full name" wins over "name" in an alternation. */
const alt = (phrases: readonly string[]): string =>
  [...new Set(phrases)].sort((a, b) => b.length - a.length).map(ci).join('|');

const NOT_WORD_BEFORE = '(?<![\\p{L}\\p{N}_])';
const NOT_WORD_AFTER = '(?![\\p{L}\\p{N}_])';

const UP = '\\p{Lu}';
const LO = '[\\p{Ll}\\p{M}]';
const TOKEN = `(?:(?:Mc|Mac|O['\\u2019]|D['\\u2019])?${UP}${LO}{1,24}(?:-${UP}${LO}{1,24})?)`;
const INITIAL = `${UP}\\.`;
const PARTICLE = '(?:van|von|der|den|de|del|della|di|da|du|dos|das|la|le|bin|ibn|al|el|ter|ten|zu|af)';
const NAME =
  `(?:${INITIAL}${SP}?){0,2}${TOKEN}` +
  `(?:${SP}(?:${INITIAL}${SP}?){0,2}(?:${PARTICLE}${SP}){0,2}${TOKEN}){0,3}`;
const UNCASED_NAME =
  '(?:\\p{Script=Han}{2,4}|\\p{Script=Hangul}{2,4}|\\p{Script=Katakana}{2,10}' +
  `|\\p{Script=Arabic}{2,20}(?:${SP}\\p{Script=Arabic}{2,20})?` +
  `|\\p{Script=Hebrew}{2,15}(?:${SP}\\p{Script=Hebrew}{2,15})?` +
  `|\\p{Script=Devanagari}{2,20}(?:${SP}\\p{Script=Devanagari}{2,20})?` +
  '|\\p{Script=Thai}{2,20})';

// ---------------------------------------------------------------------------
// Cue vocabularies (the 24 library languages; see the language policy)
// ---------------------------------------------------------------------------

/** "my name is" and its equivalents: the strongest evidence for a person. */
const SELF_INTRO = [
  'my name is', "my name's", 'my full name is', 'i am called', 'call me', 'me llamo', 'mi nombre es',
  "je m'appelle", 'mon nom est', 'ich heiße', 'ich heisse', 'mein name ist', 'mi chiamo', 'il mio nome è',
  'meu nome é', 'me chamo', 'mijn naam is', 'ik heet', 'nazywam się', 'mam na imię', 'benim adım',
  'adım', 'ismim', 'mənim adım', 'menim adim', 'меня зовут', 'моё имя', 'мое имя', 'мене звати', "моє ім'я",
  'numele meu este', 'mă numesc', 'ma numesc', 'nama saya', 'tên tôi là', 'tôi tên là', 'με λένε',
  'ονομάζομαι', 'το όνομά μου είναι', '我叫', '我的名字是', '私の名前は', 'اسمي', 'שמי',
  'קוראים לי', 'اسم من', 'نام من', 'मेरा नाम', 'ฉันชื่อ', 'ผมชื่อ',
];

/** Form labels whose value is a person. `name` alone is weaker: it also labels services. */
const NAME_LABELS = [
  'full name', 'first name', 'last name', 'given name', 'surname', 'family name', 'legal name', 'patient name',
  'patient', 'customer name', 'client name', 'contact name', 'contact person', 'account holder', 'cardholder',
  'card holder', 'beneficiary', 'recipient name', 'applicant', 'employee name', 'guardian', 'next of kin',
  'emergency contact', 'signed by', 'signature', 'attn', 'attention', 'c/o', 'nombre completo', 'apellido',
  'nom complet', 'prénom', 'vorname', 'nachname', 'cognome', 'nome completo', 'sobrenome', 'voornaam',
  'achternaam', 'imię', 'nazwisko', 'ad soyad', 'soyadı', 'soyad', 'фамилия',
  'отчество', 'ім\'я', 'прізвище', 'nume', 'prenume', 'nama lengkap', 'họ tên', 'họ và tên', 'όνομα',
  'επώνυμο', '姓名', '氏名', '이름', 'الاسم', 'שם', 'نام', 'नाम', 'ชื่อ',
];
const GENERIC_NAME_LABELS = ['name', 'nombre', 'nom', 'nome', 'naam', 'isim', 'ad', 'adı', 'имя'];

const HONORIFICS = [
  'mr', 'mrs', 'ms', 'mx', 'miss', 'dr', 'prof', 'sir', 'dame', 'madam', 'mister', 'señor', 'señora', 'sr',
  'sra', 'srta', 'doña', 'herr', 'frau', 'monsieur', 'madame', 'mademoiselle', 'mme', 'mlle', 'signor',
  'signora', 'sig', 'dott', 'senhor', 'senhora', 'meneer', 'mevrouw', 'dhr', 'mevr', 'pan', 'pani', 'sayın',
  'cənab', 'господин', 'госпожа', 'г-н', 'г-жа', 'пан', 'пані', 'domnul', 'doamna', 'bapak', 'ibu', 'ông',
  'bà', 'κύριος', 'κυρία',
];

const GREETINGS = [
  'hi', 'hello', 'hey', 'dear', 'good morning', 'good afternoon', 'good evening', 'hola', 'estimado',
  'estimada', 'bonjour', 'salut', 'cher', 'chère', 'hallo', 'liebe', 'lieber', 'sehr geehrte', 'sehr geehrter',
  'ciao', 'caro', 'cara', 'gentile', 'olá', 'oi', 'prezado', 'prezada', 'beste', 'merhaba', 'sayın', 'salam',
  'hörmətli', 'привет', 'здравствуйте', 'уважаемый', 'уважаемая', 'шановний', 'шановна', 'cześć',
  'szanowny', 'szanowna', 'dragă', 'stimate', 'halo', 'xin chào', 'γεια σου', 'αγαπητέ', 'αγαπητή',
];

const SIGN_OFFS = [
  'regards', 'best regards', 'kind regards', 'warm regards', 'best', 'thanks', 'thank you', 'many thanks',
  'cheers', 'sincerely', 'yours sincerely', 'yours truly', 'yours', 'all the best', 'mit freundlichen grüßen',
  'viele grüße', 'beste grüße', 'cordialement', 'bien à vous', 'saludos', 'atentamente', 'un saludo',
  'cordiali saluti', 'distinti saluti', 'atenciosamente', 'abraços', 'met vriendelijke groet', 'groeten',
  'pozdrawiam', 'z poważaniem', 'saygılarımla', 'iyi çalışmalar', 'hörmətlə', 'с уважением', 'з повагою',
  'cu stimă', 'cu stima', 'salam hormat', 'trân trọng', 'με εκτίμηση',
];

/** Verbs and phrases that put a person after them, weaker than an introduction. */
const PERSON_VERBS = [
  'spoke with', 'spoke to', 'talked with', 'talked to', 'met with', 'emailed', 'texted', 'messaged', 'called',
  'phoned', 'contacted', 'assigned to', 'reported by', 'requested by', 'submitted by', 'approved by',
  'reviewed by', 'created by', 'written by', 'prepared by', 'handled by', 'referred by', 'seen by',
  'treated by', 'married to', 'son of', 'daughter of', 'wife of', 'husband of', 'mother of', 'father of',
  'named', 'patient', 'customer', 'client', 'tenant', 'employee', 'student', 'colleague', 'friend', 'neighbour',
  'neighbor', 'his wife', 'her husband', 'my wife', 'my husband', 'my son', 'my daughter', 'my mother',
  'my father', 'my brother', 'my sister', 'my friend', 'my colleague',
];

/** "I'm", "Ich bin": also introduce jobs and nationalities, so they need a known name. */
const WEAK_INTROS = [
  "i'm", 'i am', 'this is', "it's", 'ich bin', 'je suis', 'soy', 'sono', 'sou', 'eu sou', 'ik ben', 'jestem',
];

/** A copula between a cue and its value: "Adresse ist", "teléfono es", "numer telefonu to". */
const COPULA = '(?:is|was|are|ist|war|est|este|es|era|è|é|jest|to|это|це|adalah|là|είναι|olan)';

const KO_SURNAME =
  '(?:남궁|황보|제갈|선우|독고|사공|서문|[김이박최정강조윤장임한오서신권황안송류유전홍고문양손배백허남심노하곽성차주우구민진나지엄채원천방공현함변염여추도소석선설마길연위표명기반왕금옥육인맹모탁국어은편용예경봉사부가복태목형피두감음빈동온시호범좌팽승간상갈단견당])';

/** Korean nouns that start like a surname but say what someone is, not who. */
const KO_NOT_NAME = new Set([
  '선생님', '선생', '간호사', '기자', '주부', '가수', '배우', '변호사', '공무원', '사장', '사장님', '경찰', '교수',
  '교수님', '교사', '대학생', '회사원', '개발자', '한국인', '한국사람', '미국인', '중국인', '일본인', '남자', '여자',
  '사람', '주인', '고객', '고객님', '부모', '부장', '부장님', '과장', '과장님', '대리', '이사', '이사님', '팀장',
  '정상', '기사', '조교', '박사', '전문가', '안내원', '상담원', '직원', '신입', '신입생', '성인', '노인', '유학생',
]);

const PERSON_CONTEXT = new RegExp(
  `${NOT_WORD_BEFORE}(?:${alt([
    'said', 'says', 'told', 'asked', 'wrote', 'called', 'emailed', 'texted', 'replied', 'lives', 'lived', 'born',
    'died', 'aged', 'years old', 'his', 'her', 'him', 'she', 'he', 'patient', 'customer', 'client', 'employee',
    'colleague', 'friend', 'wife', 'husband', 'son', 'daughter', 'mother', 'father', 'brother', 'sister',
    'phone', 'email', 'address', 'contact', 'diagnosed', 'admitted', 'signed',
  ])})${NOT_WORD_AFTER}`,
  'u',
);

const ADDRESS_CUES = [
  'lives at', 'living at', 'live at', 'resides at', 'residing at', 'located at', 'staying at', 'moved to',
  'address is', 'address', 'home address', 'billing address', 'shipping address', 'mailing address',
  'postal address', 'ship to', 'shipping to', 'deliver to', 'delivery to', 'send it to', 'mail it to',
  'wohnt in der', 'wohnt am', 'wohnt in', 'wohne in der', 'wohne am', 'wohne in', "j'habite au", "j'habite à",
  "j'habite", 'vivo en la', 'vivo en', 'abito in', 'moro na', 'moro em', 'woon aan', 'woon op', 'woon in',
  'mieszkam na', 'mieszkam przy', 'mieszkam w', 'yaşayıram', 'живу на', 'живу по адресу', 'живу в', 'i live at', 'anschrift', 'adresse', 'habite au', 'habite à', 'habite',
  'vive en la', 'vive en', 'dirección', 'direccion', 'domicilio', 'abita in', 'indirizzo', 'mora na', 'mora em',
  'mora no', 'endereço', 'woont aan', 'woont op', 'woont in', 'adres', 'mieszka na', 'mieszka przy',
  'mieszka w', 'ikamet adresi', 'ünvan', 'unvan', 'yaşayış ünvanı', 'живет на', 'живёт на', 'живет по адресу',
  'проживает по адресу', 'адрес', 'живе на', 'адреса', 'locuiește pe', 'locuieste pe', 'adresa', 'tinggal di',
  'alamat', 'sống tại', 'địa chỉ', 'μένει στην', 'μένει στο', 'διεύθυνση', '住址', '地址', '住所', '주소',
  'العنوان', 'عنوان', 'כתובת', 'آدرس', 'पता', 'ที่อยู่',
];

const DOB_CUES = [
  'date of birth', 'birth date', 'birthdate', 'born on', 'born in', 'born', 'dob', 'd.o.b', 'birthday',
  'geburtsdatum', 'geboren am', 'geboren', 'geb', 'date de naissance', 'né le', 'née le', 'fecha de nacimiento',
  'nacido el', 'nacida el', 'data di nascita', 'nato il', 'nata il', 'data de nascimento', 'nascido em',
  'nascida em', 'geboortedatum', 'geboren op', 'data urodzenia', 'urodzony', 'urodzona', 'doğum tarihi',
  'doğum tarixi', 'dogum tarixi', 'дата рождения', 'родился', 'родилась', 'дата народження', 'народився',
  'народилася', 'data nașterii', 'data nasterii', 'născut', 'născută', 'tanggal lahir', 'ngày sinh',
  'ημερομηνία γέννησης', 'γεννήθηκε', '出生日期', '生年月日', '생년월일', 'تاريخ الميلاد', 'תאריך לידה',
  'تاریخ تولد', 'जन्म तिथि', 'วันเกิด',
];

const LIFE_EVENT_CUES = [
  'admitted on', 'admitted', 'discharged on', 'discharged', 'date of death', 'died on', 'passed away on',
  'deceased on', 'surgery on', 'surgery date', 'operated on', 'diagnosed on', 'diagnosed in', 'appointment on',
  'appointment date', 'visit date', 'date of visit', 'date of service', 'hired on', 'start date', 'married on',
  'divorced on', 'arrested on', 'aufgenommen am', 'entlassen am', 'gestorben am', 'admis le', 'décédé le',
  'ingresó el', 'falleció el', 'ricoverato il', 'internado em', 'opgenomen op', 'przyjęty', 'yatış tarihi',
  'поступил', 'дата смерти',
];

/** Events tied to one person; a date later in the same clause is theirs. */
const EVENT_NOUNS = [
  'appointment', 'consultation', 'surgery', 'operation', 'admission', 'check-up', 'checkup', 'follow-up',
  'procedure', 'vaccination', 'termin', 'rendez-vous', 'cita', 'appuntamento', 'consulta', 'afspraak', 'wizyta',
  'randevu', 'приём', 'прием', 'запись',
];

const ACCOUNT_CUES = [
  'account number', 'account no', 'account #', 'account id', 'acct no', 'acct #', 'acct', 'a/c', 'customer id',
  'customer number', 'customer no', 'client id', 'client number', 'member id', 'member number',
  'membership number', 'membership no', 'policy number', 'policy no', 'policy #', 'claim number', 'claim no',
  'claim #', 'passport number', 'passport no', 'passport #', 'passport', "driver's license number",
  "driver's license", 'drivers license', "driver's licence", 'driving licence number', 'driving licence',
  'license number', 'licence number', 'license no', 'dl #', 'national id number', 'national id', 'id number',
  'identity card number', 'id card number', 'id card', 'mrn', 'medical record number', 'medical record no',
  'patient id', 'patient number', 'health card number', 'health insurance number', 'insurance number',
  'insurance id', 'subscriber id', 'employee id', 'employee number', 'employee no', 'staff id', 'staff number',
  'student id', 'student number', 'badge number', 'case number', 'case no', 'case #', 'docket number', 'tax id',
  'taxpayer id', 'tin', 'routing number', 'sort code', 'bsb', 'card ending in', 'card ending', 'ending in',
  'last four digits', 'last 4 digits', 'wallet address', 'imei', 'sim number', 'vehicle registration',
  'license plate', 'licence plate', 'plate number', 'kontonummer', 'kundennummer', 'mitgliedsnummer',
  'versicherungsnummer', 'versichertennummer', 'personalausweisnummer', 'reisepassnummer', 'steuernummer',
  'numéro de compte', 'numéro client', 'numéro de passeport', 'numéro de sécurité sociale', 'numéro fiscal',
  'número de cuenta', 'número de cliente', 'número de pasaporte', 'número de póliza', 'número de socio',
  'numero di conto', 'codice cliente', 'numero di passaporto', 'numero cliente', 'número da conta',
  'número do cliente', 'número do passaporte', 'número de contribuinte', 'rekeningnummer', 'klantnummer',
  'paspoortnummer', 'polisnummer', 'numer konta', 'numer klienta', 'numer paszportu', 'numer polisy',
  'hesap numarası', 'hesap no', 'müşteri numarası', 'müşteri no', 'pasaport numarası', 'pasaport no',
  'hesab nömrəsi', 'müştəri nömrəsi', 'pasport nömrəsi', 'şəxsiyyət vəsiqəsi', 'fin kod', 'fin',
  'номер счета', 'номер счёта', 'лицевой счет', 'лицевой счёт', 'номер паспорта', 'номер клиента',
  'номер полиса', 'номер рахунку', 'номер клієнта', 'numărul contului', 'numar cont', 'cod client',
  'numărul pașaportului', 'nomor rekening', 'nomor pelanggan', 'nomor paspor', 'số tài khoản',
  'số hộ chiếu', 'mã khách hàng', 'αριθμός λογαριασμού', 'αριθμός διαβατηρίου', 'αριθμός πελάτη', '账号',
  '账户', '卡号', '护照号', '口座番号', '会員番号', '계좌번호', '여권번호', 'رقم الحساب', 'رقم جواز السفر',
  'מספר חשבון', 'מספר דרכון', 'شماره حساب', 'شماره پاسپورت', 'खाता संख्या', 'खाता नंबर', 'เลขที่บัญชี',
];

/** Labels whose number is a business reference, not a person's identifier. */
const NOT_ACCOUNT = new RegExp(
  `${NOT_WORD_BEFORE}(?:${alt([
    'order', 'invoice', 'ticket', 'tracking', 'shipment', 'purchase order', 'po', 'version', 'build', 'release',
    'isbn', 'issn', 'doi', 'icd', 'jira', 'issue', 'pull request', 'pr', 'commit', 'page', 'line', 'room', 'flight',
    'gate', 'seat', 'table', 'model', 'part', 'sku', 'item', 'product', 'transaction', 'reference', 'ref',
    'confirmation', 'booking', 'batch', 'lot', 'serial',
  ])})${NOT_WORD_AFTER}`,
  'u',
);

const PHONE_CUES = [
  'call me at', 'call me on', 'call me', 'call', 'phone number', 'phone', 'telephone', 'tel', 'mobile', 'cell',
  'cellphone', 'text me at', 'text me', 'reach me at', 'reach me on', 'whatsapp', 'viber', 'contact number',
  'my number is', 'my number', 'fax', 'telefon', 'handy', 'telefonnummer', 'handynummer', 'téléphone',
  'portable', 'numéro de téléphone', 'teléfono', 'número de teléfono', 'móvil', 'celular', 'telefono',
  'numero di telefono', 'cellulare', 'telemóvel', 'telefone', 'número de telefone', 'nr telefonu', 'nr tel',
  'telefoonnummer', 'mobiel', 'numer telefonu', 'komórka', 'telefon numarası', 'cep telefonu', 'cep',
  'telefon nömrəsi', 'mobil nömrə', 'телефон', 'номер телефона', 'мобильный', 'номер телефону', 'nomor telepon',
  'nomor hp', 'số điện thoại', 'sđt', 'τηλέφωνο', 'κινητό', '电话', '手机', '電話番号', '전화번호', '휴대폰',
  'هاتف', 'رقم الهاتف', 'טלפון', 'تلفن', 'شماره تلفن', 'फ़ोन', 'फोन नंबर', 'मोबाइल', 'โทร', 'เบอร์โทร',
];

const SECRET_CUES = [
  'password', 'passwd', 'pwd', 'passcode', 'pass code', 'pin code', 'pin', 'otp', 'one-time code',
  'one time code', 'one-time password', 'verification code', 'security code', '2fa code', 'auth code',
  'access code', 'recovery code', 'backup code', 'security answer', 'secret answer', 'wifi password',
  'wi-fi password', 'passphrase', 'parol', 'parola', 'şifre', 'şifrə', 'contraseña', 'clave', 'mot de passe',
  'senha', 'passwort', 'kennwort', 'wachtwoord', 'hasło', 'пароль', 'kata sandi', 'mật khẩu', 'κωδικός',
  '密码', 'パスワード', '비밀번호', 'كلمة المرور', 'סיסמה', 'رمز عبور', 'पासवर्ड', 'รหัสผ่าน',
];

/** Words that follow "password is" in sentences about passwords rather than ones that give one. */
const NOT_A_SECRET = new Set(
  ('required incorrect invalid wrong missing empty expired reset too not the a an set changed correct weak strong ' +
    'valid ok okay case sensitive mandatory optional needed saved stored hidden encrypted hashed protected secure ' +
    'insecure same different long short new old being still now also only my your his her our their this that it ' +
    'there here and or but because when if forgotten lost unknown blank null none undefined changeable').split(' '),
);

const HANDLE_CUES = [
  'username', 'user name', 'login', 'handle', 'nickname', 'nick', 'gamertag', 'discord', 'telegram', 'skype',
  'instagram', 'insta', 'ig', 'twitter', 'tiktok', 'snapchat', 'snap', 'threads', 'mastodon', 'bluesky',
  'reddit', 'kullanıcı adı', 'istifadəçi adı', 'benutzername', "nom d'utilisateur", 'nombre de usuario',
  'nome utente', 'nome de usuário', 'gebruikersnaam', 'nazwa użytkownika', 'имя пользователя', 'логин', 'ник',
];

/** Code annotations, CSS at-rules and pragmas that look like handles. */
const NOT_HANDLE = new Set(
  ('param params returns return type typedef throws deprecated see example override component injectable input ' +
    'output media import keyframes font-face supports layer tailwind apply ts-ignore ts-expect-error ts-nocheck ' +
    'jsx property interface author version since todo fixme license module namespace callback event fires ' +
    'internal private public protected readonly abstract async static template link inheritdoc summary remarks ' +
    'test before after beforeeach aftereach describe it everyone here channel all true false null function ' +
    'handler string number boolean object undefined none').split(' '),
);

const MONTHS = [
  'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november',
  'december', 'jan', 'feb', 'mar', 'apr', 'jun', 'jul', 'aug', 'sep', 'sept', 'oct', 'nov', 'dec', 'januar',
  'jänner', 'februar', 'märz', 'mai', 'juni', 'juli', 'oktober', 'dezember', 'janvier', 'février', 'mars',
  'avril', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre', 'enero', 'febrero',
  'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'setiembre', 'octubre', 'noviembre',
  'diciembre', 'gennaio', 'febbraio', 'aprile', 'maggio', 'giugno', 'luglio', 'settembre', 'ottobre',
  'dicembre', 'janeiro', 'fevereiro', 'março', 'maio', 'junho', 'julho', 'setembro', 'outubro', 'novembro',
  'dezembro', 'januari', 'februari', 'maart', 'mei', 'augustus', 'ocak', 'şubat', 'mart', 'nisan', 'mayıs',
  'haziran', 'temmuz', 'ağustos', 'eylül', 'ekim', 'kasım', 'aralık', 'yanvar', 'fevral', 'aprel', 'iyun',
  'iyul', 'avqust', 'sentyabr', 'oktyabr', 'noyabr', 'dekabr', 'января', 'февраля', 'марта', 'апреля', 'мая',
  'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря', 'січня', 'лютого', 'березня',
  'квітня', 'травня', 'червня', 'липня', 'серпня', 'вересня', 'жовтня', 'листопада', 'грудня', 'stycznia',
  'lutego', 'marca', 'kwietnia', 'maja', 'czerwca', 'lipca', 'sierpnia', 'września', 'października',
  'listopada', 'grudnia', 'ianuarie', 'februarie', 'martie', 'aprilie', 'iunie', 'iulie', 'septembrie',
  'octombrie', 'noiembrie', 'decembrie', 'maret', 'agustus', 'desember', 'ιανουαρίου', 'φεβρουαρίου',
  'μαρτίου', 'απριλίου', 'μαΐου', 'ιουνίου', 'ιουλίου', 'αυγούστου', 'σεπτεμβρίου', 'οκτωβρίου',
  'νοεμβρίου', 'δεκεμβρίου',
];

const ORDINAL = '(?:st|nd|rd|th|er|e|º|°)?';
const MONTH = `(?:${alt(MONTHS)})\\.?`;
const DATE =
  '(?:' +
  '(?:19|20)\\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\\d|3[01])' +
  '|(?:0?[1-9]|[12]\\d|3[01])[-/.](?:0?[1-9]|[12]\\d|3[01])[-/.](?:(?:19|20)\\d{2}|\\d{2})' +
  `|(?:0?[1-9]|[12]\\d|3[01])${ORDINAL}\\.?${SP}+(?:(?:de|of)${SP}+)?${MONTH}(?:,?${SP}+(?:de${SP}+)?(?:19|20)\\d{2})?` +
  `|${MONTH}${SP}+(?:0?[1-9]|[12]\\d|3[01])${ORDINAL}(?:,?${SP}+(?:19|20)\\d{2})?` +
  `|${MONTH}${SP}+(?:19|20)\\d{2}` +
  '|(?:19|20)\\d{2}年\\d{1,2}月\\d{1,2}日' +
  `|(?:19|20)\\d{2}년${SP}?\\d{1,2}월${SP}?\\d{1,2}일` +
  `|ngày${SP}+\\d{1,2}${SP}+tháng${SP}+\\d{1,2}(?:${SP}+năm${SP}+(?:19|20)\\d{2})?` +
  ')';

// Street types. "Hauptstraße" carries its type as a suffix; "rue de la Paix"
// and "ul. Marszałkowska" put it first; "Main Street" puts it last.
const STREET_SUFFIX_EN =
  '(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Square|Sq|Terrace|Ter|' +
  'Way|Parkway|Pkwy|Highway|Hwy|Circle|Cir|Trail|Trl|Close|Crescent|Cres|Row|Gardens|Gdns|Mews|Walk|Alley|' +
  'Plaza|Loop|Pike|Path|Grove|Heights|Hts)\\.?';
const STREET_PREFIX = alt([
  'rue', 'avenue', 'av.', 'bd', 'boulevard', 'chemin', 'allée', 'impasse', 'place', 'quai', 'cours', 'route',
  'calle', 'c/', 'avenida', 'avda.', 'paseo', 'plaza', 'camino', 'carrer', 'carretera', 'ronda', 'via', 'viale',
  'piazza', 'corso', 'largo', 'vicolo', 'strada', 'rua', 'travessa', 'praça', 'praca', 'alameda', 'estrada',
  'calea', 'aleea', 'bulevardul', 'șoseaua', 'soseaua', 'ulica', 'ul.', 'aleja', 'al.', 'plac', 'os.',
  'osiedle', 'улица', 'ул.', 'проспект', 'пр-т', 'пр.', 'переулок', 'пер.', 'шоссе', 'бульвар', 'б-р',
  'вулиця', 'вул.', 'площа', 'οδός', 'οδ.', 'λεωφόρος', 'λεωφ.', 'jalan', 'jl.', 'đường', 'phố',
]);
const STREET_SUFFIX_ATTACHED =
  '(?:straße|strasse|str\\.|weg|gasse|allee|platz|damm|ufer|steig|pfad|chaussee|straat|laan|gracht|' +
  'plein|kade|singel|dijk|gatan|vägen|veien|gata)';
const STREET_WORD_AFTER = alt([
  'caddesi', 'cad.', 'cd.', 'sokak', 'sokağı', 'sok.', 'sk.', 'bulvarı', 'blv.', 'mahallesi', 'mah.', 'mh.',
  'küçəsi', 'küç.', 'prospekti', 'pr.', 'döngəsi', 'məhəlləsi', 'qəsəbəsi', 'straße', 'strasse', 'str.',
  'weg', 'allee', 'platz', 'gasse',
]);
const STREET_PARTICLE = '(?:de|del|de la|des|du|da|do|dos|das|di|della|delle|dei|le|la|les|el|los|las|san|santa|são|sur|y)';
const NUM = '\\d{1,5}[A-Za-z]?(?:[-/]\\d{1,4}[A-Za-z]?)?';
const UPW = `${UP}[\\p{L}\\p{M}'\\u2019.-]{0,24}`;
const UNIT = `(?:,?${SP}*(?:${alt(['apt', 'apartment', 'suite', 'ste', 'unit', 'flat', 'floor', 'fl', 'room', 'rm', 'bldg', 'building', 'wohnung', 'whg', 'etage', 'piso', 'apto', 'daire', 'mənzil', 'kv.', 'кв.'])})\\.?${SP}*#?${SP}?[A-Za-z0-9-]{1,6}|,?${SP}*#${SP}?[A-Za-z0-9-]{1,6})`;
// No dots inside city words: "Berlin. Geburtsdatum" is a city and a new sentence.
const CITY = `(?:St\\.${SP})?${UP}[\\p{L}\\p{M}'\\u2019-]{1,30}(?:${SP}${UP}[\\p{L}\\p{M}'\\u2019-]{1,30}){0,2}`;
const POSTAL_TAIL =
  '(?:' +
  `${CITY},?${SP}+[A-Z]{2}${SP}+\\d{5}(?:-\\d{4})?` + // Springfield, IL 62704
  `|${CITY},?${SP}+[A-Z]\\d[A-Z]${SP}?\\d[A-Z]\\d` + // Ottawa, ON K1A 0B1 (province before it handled by CITY)
  `|${CITY},?${SP}+[A-Z]{1,2}\\d[A-Z\\d]?${SP}?\\d[A-Z]{2}` + // London SW1A 1AA
  `|\\d{4}${SP}?[A-Z]{2}${SP}+${CITY}` + // 1012 AB Amsterdam
  `|\\d{2}-\\d{3}${SP}+${CITY}` + // 00-001 Warszawa
  `|\\d{4,6}${SP}+${CITY}` + // 75008 Paris, 10115 Berlin
  `|${CITY},?${SP}+\\d{4,6}` + // Baku 1000
  `|${CITY}` +
  ')';

// Separators between digit groups are required, so a run of digits splits one
// way only and a failed match cannot backtrack through every partition.
const PHONE_GROUPED = `\\+?(?:\\(\\d{1,4}\\)|\\d{1,5})(?:${SP}?\\(\\d{1,5}\\)|[ .\\-]\\d{1,8}){1,6}`;

// ---------------------------------------------------------------------------
// Compiled patterns, built on first use so importing the library stays cheap
// ---------------------------------------------------------------------------

interface Compiled {
  selfIntro: RegExp;
  nameLabel: RegExp;
  genericNameLabel: RegExp;
  honorific: RegExp;
  greeting: RegExp;
  signOff: RegExp;
  personVerb: RegExp;
  emailHeader: RegExp;
  nameBeforeEmail: RegExp;
  nameSuffixCue: RegExp;
  koreanIntro: RegExp;
  nameRun: RegExp;
  streetEn: RegExp;
  streetPrefix: RegExp;
  streetAttached: RegExp;
  streetWordAfter: RegExp;
  poBox: RegExp;
  zhAddress: RegExp;
  jaAddress: RegExp;
  koAddress: RegExp;
  addressCue: RegExp;
  postalTail: RegExp;
  dobCue: RegExp;
  lifeCue: RegExp;
  eventDate: RegExp;
  date: RegExp;
  birthYear: RegExp;
  accountCue: RegExp;
  phoneCue: RegExp;
  phoneValue: RegExp;
  phoneIntl: RegExp;
  phoneNanp: RegExp;
  secretCue: RegExp;
  handleCue: RegExp;
  atHandle: RegExp;
  profileUrl: RegExp;
  personalQueryUrl: RegExp;
}

let compiled: Compiled | undefined;

function patterns(): Compiled {
  if (compiled) return compiled;
  const g = (source: string): RegExp => new RegExp(source, 'gdu');
  const one = (source: string): RegExp => new RegExp(source, 'du');
  const anyName = `(${NAME}|${UNCASED_NAME})`;
  compiled = {
    selfIntro: g(`${NOT_WORD_BEFORE}(?:${alt(SELF_INTRO)})${SP}*[:,]?${SP}*["'\\u201C\\u00AB]?${anyName}`),
    nameLabel: g(`${NOT_WORD_BEFORE}(?:${alt(NAME_LABELS)})${SP}*[:=\\uFF1A]${SP}*["'\\u201C]?${anyName}`),
    genericNameLabel: g(`${NOT_WORD_BEFORE}(?:${alt(GENERIC_NAME_LABELS)})${SP}*[:=\\uFF1A]${SP}*["'\\u201C]?(${NAME})`),
    honorific: g(`${NOT_WORD_BEFORE}(?:${alt(HONORIFICS)})\\.?${SP}+(${NAME})`),
    greeting: g(`(?:^|[\\n.!?]${SP}*)(?:${alt(GREETINGS)})${SP}+(${NAME})(?=${SP}*(?:[,!:\\n]|$))`),
    signOff: g(`${NOT_WORD_BEFORE}(?:${alt(SIGN_OFFS)})${SP}*[,!.]?${SP}*\\r?\\n${SP}*(${NAME})(?=${SP}*(?:\\r?\\n|$))`),
    personVerb: g(`${NOT_WORD_BEFORE}(?:${alt([...PERSON_VERBS, ...WEAK_INTROS])})${SP}+(${NAME})`),
    emailHeader: g(`(?:^|\\n)${SP}*(?:From|To|Cc|Bcc|Reply-To|De|Von|An|Para|À|Da|Van|Od|Kimden|Kime|От|Кому)${SP}*:${SP}*(${NAME})${SP}*(?:<|\\r?\\n|$)`),
    nameBeforeEmail: g(`(${NAME})${SP}*[<(][A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,24}[>)]`),
    nameSuffixCue: g(`(\\p{Script=Han}{2,4}|\\p{Script=Katakana}{2,10})(?:と申します|といいます)|(${NAME})${SP}+(?:Bey|Hanım|Hanim|bəy|xanım|müəllim|müəllimə)${NOT_WORD_AFTER}`),
    // "저는 김민준입니다": Hangul runs straight into the copula, so the name is cut at it.
    koreanIntro: g(`(?:저는|제${SP}*이름은|나는|내${SP}*이름은)${SP}*(${KO_SURNAME}\\p{Script=Hangul}{1,2}?)(?:입니다|이에요|예요|이야|이고|이며|(?:이)?라고${SP}*합니다)`),
    nameRun: g(`${NOT_WORD_BEFORE}${NAME}${NOT_WORD_AFTER}`),
    streetEn: g(
      `${NOT_WORD_BEFORE}${NUM}${SP}+(?:[NSEW]{1,2}\\.?${SP}+)?(?:(?:${UPW}|\\d{1,3}(?:st|nd|rd|th))${SP}+){1,4}${STREET_SUFFIX_EN}${NOT_WORD_AFTER}(?:${UNIT})?`,
    ),
    streetPrefix: g(
      `${NOT_WORD_BEFORE}(?:${NUM},?${SP}+)?(?:${STREET_PREFIX})${SP}*(?:(?:${STREET_PARTICLE})${SP}+){0,3}${UPW}(?:${SP}+(?:(?:${STREET_PARTICLE})${SP}+){0,2}${UPW}){0,3}(?:,?${SP}*(?:n\\.?[º°o]?|nº|no\\.?|nr\\.?|д\\.|дом|№|number)?${SP}*${NUM})?(?:${UNIT})?`,
    ),
    streetAttached: g(
      `${NOT_WORD_BEFORE}(?:${UPW}${SP}+)?${UP}[\\p{Ll}\\p{M}ß-]{1,30}?${STREET_SUFFIX_ATTACHED}${SP}+\\d{1,4}[a-zA-Z]?(?:[-/]\\d{1,4})?(?:${UNIT})?`,
    ),
    streetWordAfter: g(
      `${NOT_WORD_BEFORE}${UPW}(?:${SP}+${UPW}){0,2}${SP}+(?:${STREET_WORD_AFTER})(?:,?${SP}*(?:No|Nu|Numara|ev|bina|№)?[:.]?${SP}*${NUM})?`,
    ),
    poBox: g(
      `${NOT_WORD_BEFORE}(?:P\\.?${SP}?O\\.?${SP}?Box|Post${SP}+Office${SP}+Box|Postfach|Apartado(?:${SP}+de${SP}+correos)?|Caixa${SP}+Postal|Bo[iî]te${SP}+postale|Casella${SP}+postale|Posta${SP}+Kutusu|а/я)${SP}*\\d{1,7}`,
    ),
    // 北京市朝阳区建国路88号: admin units, a road, a number. Unit names exclude unit
    // suffixes and function characters, so the match starts at the place name.
    zhAddress: g(
      '(?:(?:(?![省市区县區縣镇鎮州的了在是我他她你们去住于到从向])\\p{Script=Han}){1,4}[省市区县區縣镇鎮州]){0,4}' +
        '(?:(?![省市区县區縣镇鎮州的了在是我他她你们去住于到从向路街巷弄号號])\\p{Script=Han}){1,6}(?:大道|路|街|巷|弄)' +
        '[0-9０-９]{1,5}[号號](?:[0-9０-９]{1,5}(?:室|楼|樓|层|層))?',
    ),
    // 東京都千代田区丸の内1丁目2番3号
    jaAddress: g(
      '(?:\\p{Script=Han}{1,3}[都道府県])?(?:\\p{Script=Han}{1,4}[市区町村郡]){1,2}' +
        '[\\p{Script=Han}\\p{Script=Hiragana}\\p{Script=Katakana}ー]{1,8}?[0-9０-９]{1,3}丁目' +
        '(?:[0-9０-９]{1,4}(?:番地?|[-−－]))?(?:[0-9０-９]{1,4}号?)?',
    ),
    // 서울특별시 강남구 테헤란로 123
    koAddress: g(
      `(?:\\p{Script=Hangul}{1,6}(?:특별자치시|특별시|광역시|도|시)${SP}+)?(?:\\p{Script=Hangul}{1,6}(?:시|군|구)${SP}+){1,2}` +
        `\\p{Script=Hangul}{2,10}?(?:대로|로|길)${SP}?\\d{1,4}(?:-\\d{1,4})?(?:번길${SP}?\\d{1,4})?`,
    ),
    addressCue: g(`${NOT_WORD_BEFORE}(?:${alt(ADDRESS_CUES)})${SP}*(?:${COPULA}${SP}+)?[:=\\uFF1A]?${SP}*`),
    postalTail: one(`^(?:,${SP}*|${SP}*\\r?\\n${SP}*|${SP}+)(${POSTAL_TAIL})(?:,${SP}*(${UP}[\\p{L}\\p{M}]+(?:${SP}${UP}[\\p{L}\\p{M}]+)?|[A-Z]{2,3}))?`),
    dobCue: g(`${NOT_WORD_BEFORE}(?:${alt(DOB_CUES)})\\.?${NOT_WORD_AFTER}`),
    lifeCue: g(`${NOT_WORD_BEFORE}(?:${alt(LIFE_EVENT_CUES)})${NOT_WORD_AFTER}`),
    // "appointment confirmed for Thomas Lee on 3 October 2025": an event noun, then the date later in the clause.
    eventDate: g(
      `${NOT_WORD_BEFORE}(?:${alt(EVENT_NOUNS)})${NOT_WORD_AFTER}[^.!?\\n]{0,60}?${SP}(?:on|for|am|le|el|il|em|op|w|в|на)${SP}+(${DATE})(?![\\p{L}\\p{N}])`,
    ),
    date: one(`^[\\s:=,(\\-\\u2013\\uFF1A]*(?:(?:on|in|the|am|le|el|il|em|op|w|в|на|is|was|est|ist|es|è|é|era|war|of)${SP}+){0,2}(${DATE})(?![\\p{L}\\p{N}])`),
    birthYear: one(`^[\\s:=,(\\-\\u2013\\uFF1A]*(?:in${SP}+)?((?:19|20)\\d{2})(?![\\p{L}\\p{N}])`),
    accountCue: g(`${NOT_WORD_BEFORE}(?:${alt(ACCOUNT_CUES)})${NOT_WORD_AFTER}`),
    phoneCue: g(`${NOT_WORD_BEFORE}(?:${alt(PHONE_CUES)})${NOT_WORD_AFTER}`),
    phoneValue: one(`^[\\s:=,\\-\\u2013\\uFF1A]*(?:(?:${COPULA}|at|on|number|no\\.?|#)${SP}*){0,2}[:=]?${SP}*(${PHONE_GROUPED}|\\+?\\d{7,15})(?![\\d])`),
    phoneIntl: g(`(?<![\\w+])(?:\\+[1-9]\\d{0,3}(?:${SP}?\\(\\d{1,5}\\)|[ .\\-]\\d{1,5}){2,6}|\\+[1-9]\\d{7,14})(?![\\d])`),
    phoneNanp: g(`(?<![\\w.+\\-/])\\(?[2-9]\\d{2}\\)?[\\-. ][2-9]\\d{2}[\\-. ]\\d{4}(?![\\w\\-])`),
    secretCue: g(`${NOT_WORD_BEFORE}(?:${alt(SECRET_CUES)})${NOT_WORD_AFTER}`),
    handleCue: g(`${NOT_WORD_BEFORE}(?:${alt(HANDLE_CUES)})${SP}*(?:is${SP}+|[:=]${SP}*)@?([A-Za-z0-9_](?:[A-Za-z0-9_.\\-]{1,30}[A-Za-z0-9_])?)(?![A-Za-z0-9_@])`),
    atHandle: g(`(?<![\\w.@/])@([A-Za-z0-9_](?:[A-Za-z0-9_.]{1,28}[A-Za-z0-9_])?)(?![\\w@/(\\-])`),
    profileUrl: g(
      `(?<![\\w.\\-/])(?:https?://)?(?:www\\.|m\\.)?(?:facebook\\.com|fb\\.com|instagram\\.com|github\\.com|gitlab\\.com|twitch\\.tv|behance\\.net|dribbble\\.com|soundcloud\\.com|bsky\\.app/profile|twitter\\.com|x\\.com|linkedin\\.com/in|tiktok\\.com/@|t\\.me|vk\\.com|medium\\.com/@|youtube\\.com/@|threads\\.net/@|reddit\\.com/u(?:ser)?|pinterest\\.com|snapchat\\.com/add|onlyfans\\.com|patreon\\.com)/?[A-Za-z0-9_.@\\-]{2,60}/?(?![A-Za-z0-9_./\\-])`,
    ),
    personalQueryUrl: g(
      `https?://[^\\s"'<>]{1,200}[?&](?:e-?mail|mail|name|first_?name|last_?name|full_?name|phone|tel|mobile|address|dob|birth_?date|ssn|user(?:name)?|uid|token|session|sid|api_?key|password|pwd)=[^\\s"'<>&]{1,200}[^\\s"'<>]{0,300}`,
    ),
  };
  return compiled;
}

// ---------------------------------------------------------------------------
// Recognition
// ---------------------------------------------------------------------------

interface Candidate {
  label: EntityLabel;
  start: number;
  end: number;
  confidence: number;
  risk?: Risk;
}

type Push = (label: EntityLabel, start: number, end: number, confidence: number, risk?: Risk) => void;

function groupSpan(m: RegExpExecArray, group: number): [number, number] | undefined {
  const span = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices?.[group];
  return span ? [span[0], span[1]] : undefined;
}

function each(re: RegExp, text: string, fn: (m: RegExpExecArray) => void): void {
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) re.lastIndex++;
    fn(m);
  }
}

const clamp = (n: number): number => Math.max(0, Math.min(0.99, n));
const nameTokens = (value: string): string[] => value.split(/[ \t\u00A0]+/).filter((t) => !/^\p{Lu}\.$/u.test(t));

function isSentenceStart(text: string, start: number): boolean {
  for (let i = start - 1; i >= 0; i--) {
    const ch = text[i]!;
    if (ch === ' ' || ch === '\t' || ch === '"' || ch === "'" || ch === '(' || ch === '*' || ch === '-') continue;
    return ch === '.' || ch === '!' || ch === '?' || ch === '\n' || ch === ':' || ch === '>' || ch === '#';
  }
  return true;
}

/**
 * Cut a captured name at the first token that cannot be part of one ("Alice
 * Thanks", "Bob From Accounting"), and report how much name evidence is left.
 */
function trimName(text: string, start: number, end: number): { end: number; tokens: string[] } | undefined {
  const value = text.slice(start, end);
  if (!/\p{Lu}/u.test(value[0] ?? '')) return { end, tokens: [value] }; // uncased script
  const parts = value.split(/([ \t\u00A0]+)/);
  let kept = '';
  const tokens: string[] = [];
  for (let i = 0; i < parts.length; i += 2) {
    const token = parts[i]!;
    const bare = token.replace(/\.$/, '');
    if (NON_PERSON.has(bare) && !/^\p{Lu}\.$/u.test(token)) break;
    kept += (i ? parts[i - 1]! : '') + token;
    if (!/^\p{Lu}\.$/u.test(token)) tokens.push(bare);
  }
  if (!tokens.length) return undefined;
  return { end: start + kept.length, tokens };
}

function personScore(tokens: string[], base: number): number {
  let score = base;
  const first = tokens[0]!;
  const last = tokens[tokens.length - 1]!;
  if (GIVEN_NAMES.has(first)) score += AMBIGUOUS_NAMES.has(first) ? 0.15 : 0.3;
  else if (tokens.length === 1 && SURNAMES.has(first)) score += 0.2;
  if (tokens.length > 1) {
    score += 0.05;
    if (SURNAMES.has(last)) score += AMBIGUOUS_NAMES.has(last) ? 0.15 : 0.25;
    else if (GIVEN_NAMES.has(last) && !AMBIGUOUS_NAMES.has(last)) score += 0.1;
  }
  return score;
}

function recognizePersons(text: string, p: Compiled, push: Push): void {
  const cued = (re: RegExp, base: number, group = 1, gazetteerOnly = false): void => {
    each(re, text, (m) => {
      let span = groupSpan(m, group);
      if (!span && group === 1) span = groupSpan(m, 2);
      if (!span) return;
      const trimmed = trimName(text, span[0], span[1]);
      if (!trimmed) return;
      const score = personScore(trimmed.tokens, base);
      if (gazetteerOnly && score <= base) return;
      push('private_person', span[0], trimmed.end, clamp(score + (PERSON_CONTEXT.test(window(text, span[0], trimmed.end)) ? 0.05 : 0)));
    });
  };
  cued(p.selfIntro, 0.82);
  cued(p.nameLabel, 0.75);
  cued(p.honorific, 0.75);
  cued(p.emailHeader, 0.75);
  cued(p.nameBeforeEmail, 0.7);
  cued(p.signOff, 0.66);
  cued(p.greeting, 0.6);
  cued(p.nameSuffixCue, 0.82);
  each(p.koreanIntro, text, (m) => {
    const span = groupSpan(m, 1);
    if (span && !KO_NOT_NAME.has(text.slice(span[0], span[1]))) push('private_person', span[0], span[1], 0.88);
  });
  cued(p.personVerb, 0.4, 1, true);
  // A bare "name:" also labels services and products, so it needs one more
  // signal: a known name, or two tokens that end the line like a form field.
  each(p.genericNameLabel, text, (m) => {
    const span = groupSpan(m, 1);
    if (!span) return;
    const trimmed = trimName(text, span[0], span[1]);
    if (!trimmed) return;
    const atLineEnd = /^[ \t]*(?:\r?\n|$|[,;|])/.test(text.slice(trimmed.end, trimmed.end + 3));
    const score = personScore(trimmed.tokens, 0.45) + (trimmed.tokens.length > 1 && atLineEnd ? 0.05 : 0);
    push('private_person', span[0], trimmed.end, clamp(score));
  });
  // No cue at all: capitalised runs scored on the word lists and context.
  each(p.nameRun, text, (m) => {
    let start = m.index;
    let run = m[0];
    // "Later Alice called", "Ich bin Katrin": a capitalised opener (and a particle
    // look-alike such as "bin") in front of a known name is not part of it.
    const lead = LEAD_OPENER.exec(run);
    if (lead && !GIVEN_NAMES.has(lead[1]!) && (isSentenceStart(text, start) || NON_PERSON.has(lead[1]!)) && GIVEN_NAMES.has(run.slice(lead[0].length).split(/[ \t\u00A0]/)[0]!)) {
      start += lead[0].length;
      run = run.slice(lead[0].length);
    }
    const trimmed = trimName(text, start, start + run.length);
    if (!trimmed) return;
    const { tokens } = trimmed;
    const first = tokens[0]!;
    const known = GIVEN_NAMES.has(first) || tokens.some((t, i) => i > 0 && SURNAMES.has(t));
    if (!known) return;
    // One bare known name ("Mercedes and BMW") stays under the threshold without context.
    let score = personScore(tokens, tokens.length === 1 ? 0.15 : 0.2);
    if (tokens.length === 1 && AMBIGUOUS_NAMES.has(first)) return;
    if (isSentenceStart(text, start) && AMBIGUOUS_NAMES.has(first)) score -= 0.2;
    if (PERSON_CONTEXT.test(window(text, start, trimmed.end))) score += 0.1;
    push('private_person', start, trimmed.end, clamp(score));
  });
}

const LEAD_OPENER = new RegExp(`^(\\p{Lu}[\\p{Ll}\\p{M}]+)${SP}+(?:${PARTICLE}${SP}+){0,2}(?=\\p{Lu})`, 'u');

function window(text: string, start: number, end: number, radius = 40): string {
  return text.slice(Math.max(0, start - radius), Math.min(text.length, end + radius));
}

const TAIL_STOP = new Set(['The', 'This', 'That', 'It', 'I', 'We', 'He', 'She', 'They', 'And', 'But', 'Then', 'Please', 'Thanks', 'Thank', 'Call', 'Phone', 'Email', 'Tel']);

/** Extend an address with the city/postcode line that follows it, if any. */
function withPostalTail(text: string, p: Compiled, end: number): { end: number; postal: boolean } {
  const tail = p.postalTail.exec(text.slice(end, end + 120));
  if (!tail || !tail[1]) return { end, postal: false };
  const postal = /\d/.test(tail[1]);
  // A bare city after a comma is evidence; a bare capitalised word after a space is not.
  if (!postal && !/^,/.test(tail[0]) && !/\n/.test(tail[0])) return { end, postal: false };
  if (!postal && TAIL_STOP.has(tail[1].split(/[ \t]/)[0]!)) return { end, postal: false };
  return { end: end + tail[0].length, postal };
}

/** "IP address", "email address", "wallet address": addresses that are not postal. */
const NOT_POSTAL_ADDRESS = /(?:e-?mail|ip|ipv4|ipv6|mac|wallet|memory|web|server|return|base|bind|listen|bitcoin|btc|eth|ethereum|contract|host|network|hardware|physical|virtual|logical|url|ip-)\s*$/i;

const LOWERCASE_STREET_STOP = /(?:^|\s)(?:the|on|in|at|of|a|an|to|my|our|your|and|with|for|down|up|along|across|miles|km|blocks|minutes|meters|metres|steps|times|cars|people|more|than|every)(?:\s|$)/i;

function recognizeAddresses(text: string, p: Compiled, push: Push): void {
  const structural = (re: RegExp, base: number, needsNumber: boolean): void => {
    each(re, text, (m) => {
      if (needsNumber && !/\d/.test(m[0])) return;
      if (LOWERCASE_STREET_STOP.test(m[0]) && !/\p{Lu}/u.test(m[0].replace(/^[\d\s,.-]+/, '')[0] ?? '')) return;
      const tail = withPostalTail(text, p, m.index + m[0].length);
      push('private_address', m.index, tail.end, clamp(base + (tail.postal ? 0.1 : tail.end > m.index + m[0].length ? 0.05 : 0)));
    });
  };
  structural(p.streetEn, 0.85, true);
  each(p.streetPrefix, text, (m) => {
    if (!/\d/.test(m[0])) return;
    const end = m.index + m[0].length;
    // "via Slack 3 times", "Route 66 is": a type word in prose, not an address.
    if (!/^\d/.test(m[0]) && /^[ \t]+\p{Ll}/u.test(text.slice(end, end + 3))) return;
    const tail = withPostalTail(text, p, end);
    push('private_address', m.index, tail.end, clamp(0.82 + (tail.postal ? 0.1 : tail.end > end ? 0.05 : 0)));
  });
  structural(p.streetAttached, 0.85, true);
  structural(p.streetWordAfter, 0.8, true);
  each(p.poBox, text, (m) => {
    const tail = withPostalTail(text, p, m.index + m[0].length);
    push('private_address', m.index, tail.end, 0.9);
  });
  for (const re of [p.zhAddress, p.jaAddress, p.koAddress]) {
    each(re, text, (m) => push('private_address', m.index, m.index + m[0].length, 0.86));
  }
  // A cue followed by a span with a house number or a postcode, up to the end
  // of the line or sentence.
  each(p.addressCue, text, (m) => {
    if (NOT_POSTAL_ADDRESS.test(text.slice(Math.max(0, m.index - 12), m.index))) return;
    const from = m.index + m[0].length;
    const rest = text.slice(from, from + 160);
    const stop = rest.search(/\r?\n\s*\r?\n|\.(?:\s+\p{Lu}|\s*$)|[;!?](?:\s|$)|[。！？；]|\s(?:and|but|until|since|from|for|und|et|y|e|ve|və|и)\s/u);
    let segment = (stop === -1 ? rest : rest.slice(0, stop)).replace(/[\s,.;:)"'\u201D，、]+$/u, '');
    // Two lines are allowed (street, then city); a third starts something else.
    const lines = segment.split(/\r?\n/);
    const cityLine = lines[1] !== undefined && !/[:=]/.test(lines[1]) && lines[1].trim().length <= 48 && /^\s*(?:\d|\p{Lu})/u.test(lines[1]);
    segment = (cityLine ? lines.slice(0, 2).join('\n') : lines[0]!).replace(/[\s,]+$/, '');
    if (segment.length < 6 || !/\d/.test(segment) || !/\p{L}{3}/u.test(segment)) return;
    if (/^\s*(?:0x|[0-9a-f]{2}[:-][0-9a-f]{2}|\d{1,3}\.\d{1,3}\.|\S+@\S+|https?:|[a-z0-9]{20,})/i.test(segment)) return;
    if (/^\s*(?:\d{1,2}[:.]\d{2}|\d+\s*(?:%|am|pm|kg|km|miles?|years?|days?|hours?))/i.test(segment)) return;
    // 住所は…です, 주소는 … 입니다: a topic particle before and a copula after are not the address.
    const particle = /^[ \t]*(?:は|が|は、|은|는|이|가)?[ \t:：]*/u.exec(segment)![0].length;
    const copula = /[ \t]*(?:です|でございます|입니다|이에요|예요|이다)$/u.exec(segment);
    if (copula) segment = segment.slice(0, copula.index);
    if (segment.length - particle < 6) return;
    push('private_address', from + particle, from + segment.length, 0.86);
  });
}

function recognizeDates(text: string, p: Compiled, push: Push): void {
  const after = (re: RegExp, confidence: number): void => {
    each(re, text, (m) => {
      const from = m.index + m[0].length;
      const found = p.date.exec(text.slice(from, from + 60));
      const span = found && groupSpan(found, 1);
      if (!span) return;
      push('private_date', from + span[0], from + span[1], confidence);
    });
  };
  after(p.dobCue, 0.95);
  after(p.lifeCue, 0.8);
  each(p.eventDate, text, (m) => {
    const span = groupSpan(m, 1);
    if (span) push('private_date', span[0], span[1], 0.75);
  });
  // "born in 1985": a year alone is a birth date only right after a birth cue.
  each(p.dobCue, text, (m) => {
    const from = m.index + m[0].length;
    if (p.date.exec(text.slice(from, from + 60))) return;
    const found = p.birthYear.exec(text.slice(from, from + 12));
    const span = found && groupSpan(found, 1);
    if (span) push('private_date', from + span[0], from + span[1], 0.85);
  });
}

const DATE_LIKE = /^(?:(?:19|20)\d{2}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})$/;

function recognizeAccounts(text: string, p: Compiled, push: Push): void {
  each(p.accountCue, text, (m) => {
    const before = text.slice(Math.max(0, m.index - 16), m.index);
    if (NOT_ACCOUNT.test(before)) return;
    // Short acronyms are also ordinary words ("tin can", "fin"): only their capitalised form counts.
    if (/^(?:tin|fin|mrn|bsb|imei)$/i.test(m[0]) && m[0] !== m[0].toUpperCase()) return;
    const from = m.index + m[0].length;
    const rest = text.slice(from, from + 64);
    const value = /^\.?[ \t]*(?:(?:number|no\.?|num\.?|nr\.?|#|id|code|is|was|are|of|ending|in|es|est|ist|é|è|era|war|wynosi|olan|это)[ \t]*){0,3}[:=#\-\u2013\u2014\uFF1A]?[ \t]*["'(]?([A-Za-z0-9](?:[A-Za-z0-9]|[-/.](?=[A-Za-z0-9])|[ ](?=\d)){2,33})/.exec(rest);
    if (!value) return;
    let raw = value[1]!;
    raw = raw.replace(/[ .\-/]+$/, '');
    const digits = raw.replace(/\D/g, '').length;
    const shortOk = /ending|last|sort code|bsb|ending in/i.test(m[0]);
    if (digits < (shortOk ? 4 : 3)) return;
    if (DATE_LIKE.test(raw)) return;
    if (/^\d{1,2}$/.test(raw)) return;
    const start = from + value.index + value[0].length - value[1]!.length;
    push('account_number', start, start + raw.length, 0.86);
  });
}

function phoneDigitsOk(value: string): boolean {
  const digits = value.replace(/\D/g, '').length;
  if (digits < 7 || digits > 15) return false;
  return !DATE_LIKE.test(value.trim());
}

const NOT_PHONE_BEFORE = /(?:order|invoice|ticket|ref|reference|id|sku|account|acct|isbn|serial|tracking|case|claim|policy|no\.?|#)\s*[:#]?\s*$/i;

function recognizePhones(text: string, p: Compiled, push: Push): void {
  each(p.phoneCue, text, (m) => {
    const from = m.index + m[0].length;
    const found = p.phoneValue.exec(text.slice(from, from + 48));
    const span = found && groupSpan(found, 1);
    if (!span) return;
    const value = text.slice(from + span[0], from + span[1]);
    if (!phoneDigitsOk(value)) return;
    push('private_phone', from + span[0], from + span[1], 0.9);
  });
  each(p.phoneIntl, text, (m) => {
    if (!phoneDigitsOk(m[0]) || m[0].replace(/\D/g, '').length < 8) return;
    push('private_phone', m.index, m.index + m[0].length, 0.8);
  });
  each(p.phoneNanp, text, (m) => {
    if (NOT_PHONE_BEFORE.test(text.slice(Math.max(0, m.index - 24), m.index))) return;
    push('private_phone', m.index, m.index + m[0].length, 0.62);
  });
}

function recognizeSecrets(text: string, p: Compiled, push: Push): void {
  each(p.secretCue, text, (m) => {
    const from = m.index + m[0].length;
    const rest = text.slice(from, from + 100);
    const found = /^(?:[ \t]+(?:for[ \t]+[\p{L}\p{N} .'-]{1,30}?[ \t]+)?(?:is|was|will be|would be|=|:|es|est|ist|é|è|olarak|is now|is set to|set to)|[ \t]*[:=\uFF1A])[ \t]*(?:(["'\u201C\u00AB`])([^"'\u201D\u00BB`\n]{3,64})(?=["'\u201D\u00BB`])|([^\s"'\u201D\u00BB`,;]{3,64}))/u.exec(rest);
    if (!found) return;
    const quotedValue = found[2];
    let value = quotedValue ?? found[3]!.replace(/[.!?)\]]+$/, '');
    const isNumericCue = /pin|otp|code|kod|код|코드/i.test(m[0]);
    if (isNumericCue && !/^\d{4,10}$/.test(value)) return;
    const lower = value.toLowerCase();
    if (NOT_A_SECRET.has(lower)) return;
    if (value.length < 3) return;
    const plainWord = /^\p{Ll}+$/u.test(value);
    const confidence = quotedValue !== undefined || !plainWord ? 0.9 : 0.62;
    const start = from + found[0].length - (quotedValue ?? found[3]!).length;
    value = text.slice(start, start + value.length);
    push('secret', start, start + value.length, confidence);
  });
}

function recognizeHandles(text: string, p: Compiled, push: Push): void {
  each(p.handleCue, text, (m) => {
    const span = groupSpan(m, 1);
    if (!span) return;
    const value = text.slice(span[0], span[1]).toLowerCase();
    if (NOT_A_SECRET.has(value) || NOT_HANDLE.has(value)) return;
    let start = span[0];
    if (text[start - 1] === '@') start--;
    push('private_handle', start, span[1], 0.86);
  });
  each(p.atHandle, text, (m) => {
    const name = m[1]!.toLowerCase();
    if (NOT_HANDLE.has(name)) return;
    const end = m.index + m[0].length;
    // "@app.route(" and "@pytest.mark" are decorators, not handles.
    if (/^\.[A-Za-z_]/.test(text.slice(end, end + 2))) return;
    if (/^\d+$/.test(name)) return;
    push('private_handle', m.index, m.index + m[0].length, 0.74);
  });
}

function recognizeUrls(text: string, p: Compiled, push: Push): void {
  each(p.profileUrl, text, (m) => {
    const path = m[0].replace(/^(?:https?:\/\/)?(?:www\.|m\.)?[^/]+\/(?:in\/|@|u\/|user\/|add\/)?/, '').replace(/\/$/, '');
    if (!path || /^(?:home|about|help|login|signup|share|sharer|intent|explore|search|settings|privacy|terms|policies|jobs|company|groups|pages|events|hashtag|watch|channel|c|r|p|status|features|pricing|enterprise|topics|marketplace|sponsors|orgs|organizations|trending|collections|security|notifications|new|apps|team|contact|blog|docs|download|downloads|directory|discover|gallery|live|videos|music|stream|tos|feed)$/i.test(path)) return;
    push('private_url', m.index, m.index + m[0].length, 0.8);
  });
  each(p.personalQueryUrl, text, (m) => {
    const url = m[0].replace(/[.,;:!?)\]]+$/, '');
    // A link carrying a token or session is a credential: mask all of it, ahead of the token alone.
    const credential = /[?&](?:token|session|sid|api_?key|password|pwd)=/i.test(url);
    push('private_url', m.index, m.index + url.length, credential ? 0.95 : 0.86, credential ? 'critical' : undefined);
  });
}

/** Later mentions of a confidently recognised person: "Alice Johnson ... Alice said". */
function propagatePersons(text: string, found: Candidate[], push: Push): void {
  const names = new Set<string>();
  for (const c of found) {
    if (c.label !== 'private_person' || c.confidence < 0.6) continue;
    const value = text.slice(c.start, c.end);
    names.add(value);
    for (const token of nameTokens(value)) {
      if (token.length >= 3 && !NON_PERSON.has(token) && !AMBIGUOUS_NAMES.has(token) && !/^\p{Ll}/u.test(token)) names.add(token);
    }
  }
  if (!names.size) return;
  const list = [...names].sort((a, b) => b.length - a.length).slice(0, 200).map(esc);
  const re = new RegExp(`${NOT_WORD_BEFORE}(?:${list.join('|')})${NOT_WORD_AFTER}`, 'gu');
  each(re, text, (m) => push('private_person', m.index, m.index + m[0].length, 0.8));
}

/** Merge overlapping candidates of one label into their union, keeping the best score. */
function mergeSameLabel(candidates: Candidate[]): Candidate[] {
  const byLabel = new Map<EntityLabel, Candidate[]>();
  for (const c of candidates) {
    const list = byLabel.get(c.label) ?? [];
    list.push(c);
    byLabel.set(c.label, list);
  }
  const out: Candidate[] = [];
  for (const list of byLabel.values()) {
    list.sort((a, b) => a.start - b.start || b.end - a.end);
    let current: Candidate | undefined;
    for (const c of list) {
      if (current && c.start < current.end) {
        current.end = Math.max(current.end, c.end);
        current.confidence = Math.max(current.confidence, c.confidence);
        if (c.risk === 'critical') current.risk = 'critical';
      } else {
        if (current) out.push(current);
        current = { ...c };
      }
    }
    if (current) out.push(current);
  }
  return out.sort((a, b) => a.start - b.start || a.end - b.end);
}

const LABEL_TEXT = new Map(ENTITY_DETECTORS.map((d) => [d.id, d]));

/**
 * Find people, addresses, phone numbers, personal dates, account numbers,
 * handles, personal URLs and secrets written in free text.
 *
 *   recognizeEntities('My name is Alice Johnson, I live at 12 Baker Street.')
 *   // [{ detector: 'private_person', start: 11, end: 24, confidence: 0.99, ... },
 *   //  { detector: 'private_address', start: 36, end: 52, ... }]
 */
export function recognizeEntities(text: string, options: EntityOptions = {}): EntityFinding[] {
  if (!text || text.length < 3) return [];
  const labels = new Set<EntityLabel>(options.labels ?? ENTITY_LABELS);
  const minConfidence = options.minConfidence ?? 0.5;
  const p = patterns();
  const candidates: Candidate[] = [];
  const push: Push = (label, start, end, confidence, risk) => {
    if (end > start) candidates.push(risk ? { label, start, end, confidence, risk } : { label, start, end, confidence });
  };

  if (labels.has('private_person')) recognizePersons(text, p, push);
  if (labels.has('private_address')) recognizeAddresses(text, p, push);
  if (labels.has('private_date')) recognizeDates(text, p, push);
  if (labels.has('account_number')) recognizeAccounts(text, p, push);
  if (labels.has('private_phone')) recognizePhones(text, p, push);
  if (labels.has('secret')) recognizeSecrets(text, p, push);
  if (labels.has('private_handle')) recognizeHandles(text, p, push);
  if (labels.has('private_url')) recognizeUrls(text, p, push);

  let kept = candidates.filter((c) => c.confidence >= minConfidence);
  if (labels.has('private_person') && options.propagate !== false) {
    const extra: Candidate[] = [];
    propagatePersons(text, kept, (label, start, end, confidence) => extra.push({ label, start, end, confidence }));
    kept = kept.concat(extra.filter((c) => c.confidence >= minConfidence));
  }

  return mergeSameLabel(kept).map((c) => {
    const det = LABEL_TEXT.get(c.label)!;
    return {
      detector: c.label,
      label: det.label,
      why: det.why,
      start: c.start,
      end: c.end,
      risk: c.risk ?? RISK.get(c.label)!,
      confidence: Math.round(c.confidence * 100) / 100,
    };
  });
}

/** The recogniser as a SemanticProvider, for code that already takes one. */
export function createEntityRecognizer(options: EntityOptions = {}): SemanticProvider {
  return { detect: (text: string) => recognizeEntities(text, options) };
}
