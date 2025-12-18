use jiff::Zoned;

pub trait PlatformAbstractions {
    fn get_current_time() -> Zoned;
}
