pub fn init_fs() {
    let schemes = schemes_mut().unwrap();
    schemes.insert(SchemeNamespace(0), Box::new(*b"acpi"), |_| Arc::new(Box::new(AcpiScheme::new()))).unwrap();
}

struct AcpiScheme {
    
}

impl AcpiScheme {
    pub fn new() -> AcpiScheme {
        AcpiScheme
    }
}

impl Scheme for AcpiScheme {
    fn open(&self, url: &[u8], flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');
        
