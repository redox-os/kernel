macro_rules! expand_bool(
    ($value:expr_2021) => {
        concat!($value)
    }
);

macro_rules! alternative(
    (feature: $feature:literal, then: [$($then:expr_2021),*], default: [$($default:expr_2021),*]) => {
        alternative2!(feature1: $feature, then1: [$($then),*], feature2: "", then2: [""], default: [$($default),*])
    }
);
macro_rules! saturating_sub(
    ($lhs:literal, $rhs:literal) => { concat!(
        "((", $lhs, ")>(", $rhs, "))*((", $lhs, ")-(", $rhs, "))",
    ) }
);
// Use feature1 if present, otherwise try using feature2, otherwise use default.
//
// cpu_feature_always simply means it is always enabled. Thus, if feature2, which has lower
// priority, is "always" but feature1 is "auto", feature2 will still be checked for, and feature2
// will become the fallback code.
//
// An empty string as feature is equivalent with "never".
macro_rules! alternative2(
    (feature1: $feature1:literal, then1: [$($then1:expr_2021),*], feature2: $feature2:literal, then2: [$($then2:expr_2021),*], default: [$($default:expr_2021),*]) => {
        concat!("
            .set true, 1
            .set false, 0
            40:
            .if ", expand_bool!(cfg!(cpu_feature_always = $feature1)), "
            ", $($then1,)* "
            .elseif ", expand_bool!(cfg!(cpu_feature_always = $feature2)), "
            ", $($then2,)* "
            .else
            ", $($default,)* "
            .endif
            42:
            .if ", expand_bool!(cfg!(cpu_feature_auto = $feature1)), "
            .skip -", saturating_sub!("51f - 50f", "42b - 40b"), ", 0x90
            .endif
            .if ", expand_bool!(cfg!(cpu_feature_auto = $feature2)), "
            .skip -", saturating_sub!("61f - 60f", "42b - 40b"), ", 0x90
            .endif
            41:
            ",
            // FIXME: The assembler apparently complains "invalid number of bytes" despite it being
            // quite obvious what saturating_sub does.

            // Declare them in reverse order. Last relocation wins!
            alternative_auto!("6", $feature2, [$($then2),*]),
            alternative_auto!("5", $feature1, [$($then1),*]),
        )
    };
);
macro_rules! alternative_auto(
    ($first_digit:literal, $feature:literal, [$($then:expr_2021),*]) => { concat!(
        ".if ", expand_bool!(cfg!(cpu_feature_auto = $feature)), "
        .pushsection .altcode.", $feature, ",\"a\"
        ", $first_digit, "0:
        ", $($then,)* "
        ", $first_digit, "1:
        .popsection
        .pushsection .altfeatures.", $feature, ",\"a\"
        70: .ascii \"", $feature, "\"
        71:
        .popsection
        .pushsection .altrelocs.", $feature, ",\"a\"
        .quad 70b
        .quad 71b - 70b
        .quad 40b
        .quad 42b - 40b
        .quad 41b - 40b
        .quad 0
        .quad ", $first_digit, "0b
        .quad ", $first_digit, "1b - ", $first_digit, "0b
        .popsection
        .endif
        ",
    ) }
);
