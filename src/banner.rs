//! Startup banner — red evil-eye logo + title (Windows / Linux / macOS).

use std::io::{self, IsTerminal, Write};

/// User-supplied evil-eye ASCII logo (leading pads ignored — centered at render time).
const EYE: &str = r#"
`i>~|t|()tttt|+>>l
`I}|xXJJQJJJJLC00Zdkdm0LYYxf<!'
^>{)(frrrrrrxxuXCQQ0OhbZ000000000QUn?,
'~tfjrrrrrrrrxrUQ00000*odO0Q0QJXQ000Uuuuur{i
.i)jrrrucucX0QJULQ0QZpZ0b##*kZQ0QLQQ000QCXcrcXn\+'
`-fnuznvQQCJJQQLzJ000QZkbwpdp0Q00000LCQ00QCcvuJQQJ00v:
^{z000QCCUYLJLQQQQJUQmqk##*hkqqwOmk*ZQQ00Q00000000QQ0JCJt,
'_nL000QCXxrrrrjjrnJ00L0mb*opa**bmmh#dm000QQCUC000QQZhq0Q00C(^
,1UQ00LUvrjf|[__~~___?|ruOOpaaa**aaapdbqZmOQ00whkwmma#awwZ0000Xi
lcQ00QUxj/{_<<<<<<<<ii>+fb#######kd*#######oaakk##**##aqbbm0000Lu~
<000QUnf{_>>>><<<<>>>><_-++td####adk###########*h*######*kmmbaZ00QC]
'(Q00QYx(<>><<<<><><<}tYOpokOUtud**dLmo###################*hdmO000Cujj?.
[C00Cnt[<><<<<<<><{jJkoooooooom1_\rxjruLmp*##o*##########o*#kw0000Cvrrj[
~XQ0Lu\-<<<<<<<<<></Zaooooad0nx|_>>>~]\rnJQmk**ko#########*###owQ00Qcrrj/i
,\LQQn/_><<<<<<<<>[<<+(Jhpu?~<<<<<<<>><{jcwk**o#ha*w*#########*##d000Lvrjf["
.[0QQuf?<><<<<<<>-xjCC|~<~<<>>><<<<<?]?>(Yk######bZhopma###odppZmpm000Qzrj(<,
:UQ0Xr1<<<<<<<<<<<><\/?" ^I>><<<<<<-XMBJtL#######ba#*dwQQ000000000000JUUrrt[i`
+C0Cxj]><<<<<<<<<<>,       '!>><<~{n0W%p{up*#####hdbZdZqak0mk*kZ00000Qzrrjf)~I.
.tQ0Cxf>><<<<<<<<<<!         'l><>]{jrYv[<]fYpkhahadaokmqakOwOOdbO0000QLCujt}<l'
^jQ0Cxf<<<<<<<<<<<<"         `!<~??-_}\\i><[fjJ000do#*q0wa###*bZ0000QQQJnrrf|1+"
!nL0Cxf<<<<<<<<<<<<"        .I<<<[tj/((+i<+)jvLQOdapa#oZ0qk**bpZ0000QUcvxrrrt}~"
!zQ0Cxf_><<<<<<><+~>;.     ,i><<<fXLf{~i<<+|xJQ0d##o*bwwZZwwOm000000000Jxrrrj\_"
!zQ0Cxr1<<<<<<<>~~<<<>IIl~{/]__~-fj\+<>><<}rnC0Zaoaqbwmq00000000000QCQQzrrrrrr(,
!rY0Cxr(~<<<<<<<<<<_}[1})ffjj?(\{+_<>>>><?fjXQda##am00CJLLQQCXXYJCQCuxxrrf{tjf-"
IfuCQcrj\+<<<<<<<<<<<++}rcvzft)-<<<<>>><-trcLQbkwphha*ohppwZ0QQLJUUnrrrrrrt[\)~"
.[rrYXrrj|+<<<<<<<<<<<<<<<~Ldv1-<<<>>><[frcLZhok*hpO0p***bOZ0000QLQLvxrrrrjt}?~"
.[rrrnUrrj\_><<<<<<<<<<<<<~L0c}<<>>>>?(frzQZh##am000Q00000000000Lzxxrrrrrrrr\+I.
`?1frrjjrjj}><<<<<<<+)+-~<j0u->>><_\jjrY0mda##*m000000QUJQ0XC00Uzxjrrrrrrrf[i`
,-\jrucYxrjt]~<><<<>>_}~>>!!>>>+|jjrXQQQLJZO0bZQ000QYvJXxrnujjurjrrrrrrrj{>l'
'l_trjuQUnrrjj\[+~>><~?/t_~_?|fjjrzQQ0w*kqmQqQCLQ000Qvuujjrrrrrrjjrjj\(][<i"
"~/jrruzCzxrrrjjj//tjrY0crjrrjjrcQ00Z###*hpOUcczLQ0Uxrrrrrrf(tjtffjft)?]i,
,[jrjjrcXQQYnrjjrrjjYh#*bYuuuzL000Za#####oqZ0QcfrvCXjrrrrrj|/t}rj\{--<>l.
;?jjrrrjcLQLXYzvxvXvc0a*kZOZLJQ00Oh######hq00Qctt|\rjrrrrrrjj1r/?~><<l.
;]fjjrrrnvxXQQQQQ0LLzcCwqp*#*dkbwph####kw0QCUvr/\|\1{[/rrrrrr|]_+<<I'
"~[\jrrjjrruvQ00mmOLLJccuuzQOqbkkkkhkqZ0LQCUcurf\/ttt/}}|ftjj(-~>:
'I<+(jrjjjrjC0O000QL0QQCuxUvcJLQQQQ00000QJJvxrjfrnrrrjjf{1//|]~,
.:><}jjjjfjrxXQQ0QQQQ0JxUcrunXQ0000000QLYnrjxXJzxrrrrjjt1/)}<`
'l>~1jjjrrrjrxcLCYQQvjCnxvncQ000QLzcurxvQOQQcrrrrrrrrrrj{"
.l<>>_}(rrrvurjrvcruJjrrrnzznrjvucJ0qod0Lurrrrrrrrrr(^
,i><><?)/jJQ00Uz0vfrt{ruccU000QQCvjjjrrrrrrrrjt_'
^I>><<<<1jxzxucrjrffXvnnjrrrrrrrj(frjfffjf}l.
',!i>>]|1|j)+-|]_\ff\}_?)|/ff/\)\\~<_:'
`^ll>>{|-<<<<<<<<<<<<><>ii!lI`
`^^:IIIIIIIIIII"^^'
"#;

/// Big FIGlet-style title — must spell DEVIL EYE (not EXE).
/// Every row is exactly the same width so the letters stay aligned in
/// their columns once `center_block` pads/centers each line.
const TITLE: &str = r#"
#######  ####### ##     ## ### ##          ####### ##     ## #######
##    ## ##      ##     ##  #  ##          ##       ##   ##  ##     
##    ## ##      ##     ##  #  ##          ##        ## ##   ##     
##    ## #####    ##   ##   #  ##          #####      ###    #####  
##    ## ##       ##   ##   #  ##          ##          #     ##     
##    ## ##        ## ##    #  ##          ##          #     ##     
#######  #######    ###    ### #######     #######     #     #######
"#;

const RED: &str = "\x1b[31m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Enable ANSI colors when the platform needs it (Windows). No-op on Linux/macOS.
pub fn enable_color() {
    let _ = enable_ansi_support::enable_ansi_support();
}

/// Decide whether to emit ANSI colors (all platforms).
pub fn want_color(no_color_flag: bool) -> bool {
    if no_color_flag {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("FORCE_COLOR").is_some() || std::env::var_os("CLICOLOR_FORCE").is_some() {
        return true;
    }
    io::stderr().is_terminal() || io::stdout().is_terminal()
}

/// Center each non-empty line within the widest line of the block.
///
/// Used for the eye art, where every row is independently shaped (a taper),
/// so centering row-by-row is what actually produces the eye silhouette.
fn center_block(art: &str) -> String {
    let lines: Vec<String> = art
        .lines()
        .map(|l| l.trim_end().trim_start().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let width = lines.iter().map(String::len).max().unwrap_or(0);
    lines
        .into_iter()
        .map(|line| {
            let pad = width.saturating_sub(line.len()) / 2;
            format!("{:>width$}", line, width = pad + line.len())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Center a fixed-width glyph block (e.g. the FIGlet title) as a single unit.
///
/// Unlike `center_block`, this never trims mid-block whitespace — every row
/// of a block-letter font carries meaningful trailing spaces that keep
/// letters lined up in their columns, and trimming them per row (then
/// centering each row on its own) drifts the letters out of alignment.
fn center_block_uniform(art: &str) -> String {
    let lines: Vec<&str> = art.trim_matches('\n').lines().collect();
    let width = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    lines
        .into_iter()
        .map(|line| {
            let pad = width.saturating_sub(line.len()) / 2;
            format!("{}{}", " ".repeat(pad), line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn paint_red(text: &str, use_color: bool) -> String {
    let text = text.trim_end();
    if !use_color {
        return text.to_string();
    }
    text.lines()
        .map(|line| format!("{BOLD}{RED}{line}{RESET}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Banner: giant title on top, centered red eye, then version footer.
pub fn render(use_color: bool) -> String {
    let ver = env!("CARGO_PKG_VERSION");
    let title = paint_red(&center_block_uniform(TITLE), use_color);
    let eye = paint_red(&center_block(EYE), use_color);
    format!(
        "{title}\n\n{eye}\n\
   =[ devil-eye v{ver}                                    ]\n\
+ -- --=[ authorized cyber toolkit                        ]\n\
+ -- --=[ type a number to run a module, or q to quit     ]\n\
+ -- --=[ no exploits . no malware . scope required       ]\n"
    )
}

/// Print banner to stderr unless `--no-banner` was passed.
pub fn maybe_print(no_banner: bool, use_color: bool) {
    if no_banner {
        return;
    }
    if use_color {
        enable_color();
    }
    let _ = writeln!(io::stderr(), "{}", render(use_color).trim_end());
    let _ = io::stderr().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_title_before_eye() {
        let b = render(false);
        let title = b
            .find("#######  ####### ##     ## ### ##")
            .expect("big title");
        let eye = b.find("Q00").expect("eye art");
        assert!(
            title < eye,
            "big DEVIL EYE title must appear above the eye art"
        );
        assert!(b.contains(env!("CARGO_PKG_VERSION")));
        assert!(b.contains("authorized cyber toolkit"));
        assert!(
            b.contains("#####      ###    #####"),
            "title must use Y letterform for EYE"
        );
    }

    #[test]
    fn title_rows_stay_aligned() {
        let lines: Vec<&str> = TITLE.trim_matches('\n').lines().collect();
        let width = lines[0].len();
        for line in &lines {
            assert_eq!(
                line.len(),
                width,
                "every row of the FIGlet title must be the same width, or centering will misalign the letters"
            );
        }
    }

    #[test]
    fn red_codes_when_color_enabled() {
        let b = render(true);
        assert!(b.contains(RED));
        assert!(b.contains(RESET));
    }

    #[test]
    fn eye_tip_is_centered() {
        let block = center_block(EYE);
        let lines: Vec<&str> = block.lines().collect();
        assert!(lines.len() > 3);
        let tip = lines[0];
        let wide = lines.iter().max_by_key(|l| l.len()).copied().unwrap();
        let tip_content = tip.trim_start();
        let tip_pad = tip.len() - tip_content.len();
        let tip_center = tip_pad + tip_content.len() / 2;
        let block_center = wide.len() / 2;
        let drift = tip_center.abs_diff(block_center);
        assert!(
            drift <= 2,
            "eye tip not centered: tip_center={tip_center} block_center={block_center} drift={drift}\n{tip}\n{wide}"
        );
    }
}
