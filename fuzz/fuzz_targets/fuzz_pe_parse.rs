use bolero::check;
use portex::PE;

fn main() {
    check!().for_each(|data: &[u8]| {
        // Try to parse the data as a PE file
        // This should never panic, only return errors for invalid input
        let _ = PE::parse(data);
    });
}

