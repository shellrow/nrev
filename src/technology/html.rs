//! Extract a generator from an explicitly delimited HTML head in a bounded preview.
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};

pub(crate) fn generator(preview: &str) -> Option<String> {
    let mut reader = Reader::from_str(preview.get(..preview.len().min(16 * 1024))?);
    reader.config_mut().check_end_names = false;
    reader.config_mut().allow_unmatched_ends = true;
    let mut in_head = false;
    let mut generator = None;
    for _ in 0..256 {
        let event = reader.read_event().ok()?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                let key = tag.name().as_ref().to_ascii_lowercase();
                match key.as_str() {
                    "html" if !in_head => {}
                    "head" if !in_head && !empty => in_head = true,
                    "body" if in_head => return generator,
                    "meta" if in_head => {
                        if let Some(v) = meta_value(&tag)? {
                            if generator.as_ref().is_some_and(|previous| previous != &v) {
                                return None;
                            }
                            generator = Some(v);
                        }
                    }
                    "base" | "link" if in_head => {}
                    "title" | "script" | "style" | "template" | "noscript" if in_head => {
                        if empty {
                            return None;
                        }
                        reader.read_to_end(tag.name()).ok()?;
                    }
                    _ => return None,
                }
            }
            Event::End(tag) if in_head && tag.name().as_ref().eq_ignore_ascii_case("head") => {
                return generator;
            }
            Event::Text(t) if !t.as_ref().trim().is_empty() => return None,
            Event::Eof => return None,
            _ => {}
        }
    }
    None
}

fn meta_value(tag: &BytesStart<'_>) -> Option<Option<String>> {
    let mut name = None;
    let mut content = None;
    for attribute in tag.html_attributes() {
        let attribute = attribute.ok()?;
        let value = attribute.value;
        if attribute.key.as_ref().eq_ignore_ascii_case("name")
            && name.replace(value.clone()).is_some()
        {
            return None;
        }
        if attribute.key.as_ref().eq_ignore_ascii_case("content")
            && content.replace(value).is_some()
        {
            return None;
        }
    }
    if !name.is_some_and(|n| n.eq_ignore_ascii_case("generator")) {
        return Some(None);
    }
    let content = content?;
    let text = content.trim();
    (text.len() <= super::MAX_FIELD && !text.is_empty() && !text.chars().any(char::is_control))
        .then(|| Some(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::generator;
    #[test]
    fn requires_html_head_and_skips_inert_text() {
        let accepted = "<html><head><!-- <meta name='generator' content='fake'> --><script>let s = \"<meta name='generator' content='fake'>\";</script><META CONTENT='WordPress 6.7.1' NAME=generator></head>";
        assert_eq!(generator(accepted).as_deref(), Some("WordPress 6.7.1"));
        for input in [
            "<head><meta name=generator content=GitLab>",
            "<body><meta name=generator content=Grafana></body>",
            "<head><meta data-name=generator content=Gitea></head>",
            "<head><meta name=generator content=Gitea><meta name=generator content=Grafana></head>",
            "<head><template><meta name=generator content=GitLab></template></head>",
        ] {
            assert_eq!(generator(input), None);
        }
    }
}
