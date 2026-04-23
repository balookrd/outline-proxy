macro_rules! register_labeled {
    ($reg:expr, $ty:ty, $name:literal, $help:literal, [$($label:literal),* $(,)?]) => {{
        let m = <$ty>::new(
            ::prometheus::Opts::new($name, $help),
            &[$($label),*],
        )
        .expect(concat!($name, " metric"));
        $reg.register(Box::new(m.clone()))
            .expect(concat!("register ", $name));
        m
    }};
}

macro_rules! register_scalar {
    ($reg:expr, $ty:ty, $name:literal, $help:literal) => {{
        let m = <$ty>::with_opts(::prometheus::Opts::new($name, $help))
            .expect(concat!($name, " metric"));
        $reg.register(Box::new(m.clone()))
            .expect(concat!("register ", $name));
        m
    }};
}

macro_rules! register_histogram {
    (
        $reg:expr,
        $name:literal,
        $help:literal,
        [$($bucket:expr),* $(,)?],
        [$($label:literal),* $(,)?]
    ) => {{
        let m = ::prometheus::HistogramVec::new(
            ::prometheus::HistogramOpts::new($name, $help)
                .buckets(vec![$($bucket),*]),
            &[$($label),*],
        )
        .expect(concat!($name, " metric"));
        $reg.register(Box::new(m.clone()))
            .expect(concat!("register ", $name));
        m
    }};
}

pub(crate) use register_histogram;
pub(crate) use register_labeled;
pub(crate) use register_scalar;
