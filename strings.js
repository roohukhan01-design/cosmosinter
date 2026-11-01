export const STRINGS = {
  en: { notEncrypted: 'Not encrypted', pairingExpiry: 'Pairing code expires in 5 minutes and can be used once.' },
  ur: { notEncrypted: 'غیر محفوظ کنکشن', pairingExpiry: 'پیرنگ کوڈ 5 منٹ بعد ختم ہو جائے گا اور صرف ایک بار استعمال ہو سکتا ہے۔' }
};
export function t(key, language) { return (STRINGS[language] || STRINGS.en)[key] || STRINGS.en[key] || key; }
