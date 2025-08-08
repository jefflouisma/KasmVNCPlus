use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let cfg = novnc_recorder::read_config()?;
    novnc_recorder::run(cfg)
}
