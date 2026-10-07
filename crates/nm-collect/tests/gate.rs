use nm_collect::TargetGate;
use nm_core::*;
fn device(address: &str, enrolled: bool) -> Device {
    Device {
        id: DeviceId::new(),
        display_name: "test".into(),
        management: address.parse().unwrap(),
        vendor: Vendor::Unknown,
        family: DeviceFamily::Unknown,
        role: None,
        site: None,
        credential_profile: None,
        source: EnrollmentSource::Manual,
        enrolled,
        ssh_legacy_ok: false,
        interface_roles: std::collections::BTreeMap::default(),
        tags: vec![],
    }
}
#[tokio::test]
async fn candidates_never_enter_gate() {
    let candidate = device("192.0.2.10", false);
    let enrolled = device("192.0.2.11", true);
    let gate = TargetGate::new(&[candidate, enrolled.clone()]).await;
    assert!(gate.check("192.0.2.10".parse().unwrap()).is_err());
    assert_eq!(
        gate.check("192.0.2.11".parse().unwrap()).unwrap(),
        enrolled.id
    );
}
#[tokio::test]
async fn same_ip_different_ports_are_distinct_and_unenrolled_ports_are_denied() {
    let first = device("192.0.2.1:2222", true);
    let second = device("192.0.2.1:2223", true);
    let gate = TargetGate::new(&[first.clone(), second.clone()]).await;
    assert_eq!(
        gate.check_address("192.0.2.1:2222".parse().unwrap())
            .unwrap(),
        first.id
    );
    assert_eq!(
        gate.check_address("192.0.2.1:2223".parse().unwrap())
            .unwrap(),
        second.id
    );
    assert!(gate.check_address("192.0.2.1:22".parse().unwrap()).is_err());
    assert!(gate.failures().is_empty());
}
#[tokio::test]
async fn hostname_resolves_once_and_duplicate_ips_fail_closed() {
    let enrolled = device("localhost", true);
    let gate = TargetGate::new(std::slice::from_ref(&enrolled)).await;
    assert!(!gate.addresses().is_empty());
    for ip in gate.addresses() {
        assert_eq!(gate.check(*ip).unwrap(), enrolled.id);
    }
    let first = device("192.0.2.10", true);
    let second = device("192.0.2.10", true);
    let third = device("192.0.2.10", true);
    let gate = TargetGate::new(&[first, second, third]).await;
    assert!(gate.check("192.0.2.10".parse().unwrap()).is_err());
    assert_eq!(gate.failures().len(), 3);
}
