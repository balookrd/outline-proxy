use super::*;

fn set(patterns: &[&str]) -> DomainSet {
    DomainSet::parse(&patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
}

#[test]
fn exact_and_subdomain_match() {
    let s = set(&["example.com"]);
    assert!(s.contains_domain("example.com"));
    assert!(s.contains_domain("a.example.com"));
    assert!(s.contains_domain("a.b.example.com"));
    assert!(!s.contains_domain("notexample.com"));
    assert!(!s.contains_domain("example.org"));
    assert!(!s.contains_domain("com"));
}

#[test]
fn normalization_of_patterns_and_hosts() {
    for pattern in ["Example.COM", "*.example.com", ".example.com", "example.com."] {
        let s = set(&[pattern]);
        assert!(s.contains_domain("EXAMPLE.com"), "pattern {pattern:?}");
        assert!(s.contains_domain("sub.example.com."), "pattern {pattern:?}");
    }
}

#[test]
fn catch_all_matches_everything() {
    let s = set(&["*"]);
    assert!(s.matches_all());
    assert!(!s.is_empty());
    assert!(s.contains_domain("anything.at.all"));
    assert!(s.contains_domain("localhost"));
}

#[test]
fn tld_suffix_matches_on_label_boundary() {
    let s = set(&["ru"]);
    assert!(s.contains_domain("yandex.ru"));
    assert!(s.contains_domain("ru"));
    assert!(!s.contains_domain("example.ruu"));
    assert!(!s.contains_domain("peru"));
}

#[test]
fn empty_and_invalid_patterns() {
    assert!(DomainSet::parse(&["".into()]).is_err());
    assert!(DomainSet::parse(&["  ".into()]).is_err());
    assert!(DomainSet::parse(&["*.".into()]).is_err());
    let empty = DomainSet::parse(&[]).unwrap();
    assert!(empty.is_empty());
    assert!(!empty.contains_domain("example.com"));
}

#[test]
fn suffix_count_reported() {
    let s = set(&["a.com", "b.com", "*"]);
    assert_eq!(s.suffix_count(), 2);
    assert!(s.matches_all());
}

#[tokio::test]
async fn read_domains_from_file_skips_comments_and_blanks() {
    let path =
        std::env::temp_dir().join(format!("outline-routing-domains-{}.lst", std::process::id()));
    tokio::fs::write(&path, "# comment\nexample.com\n\n  spaced.org  \n#tail\n")
        .await
        .unwrap();
    let read = read_domains_from_file(&path).await.unwrap();
    let _ = tokio::fs::remove_file(&path).await;
    assert_eq!(read, vec!["example.com".to_string(), "spaced.org".to_string()]);
}
