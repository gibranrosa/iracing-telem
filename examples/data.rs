use std::time::Duration;

use iracing_telem::{flags, safe::Client, DataUpdateResult};

fn main() -> Result<(), iracing_telem::safe::SafeError> {
    let mut c = Client::new();
    loop {
        println!("start iRacing");
        match c.wait_for_session(Duration::new(600, 0))? {
            None => {
                println!("remember to start iRacing!");
                return Ok(());
            }
            Some(mut s) => {
                let vss = s.require_var("SessionState")?;
                let vst = s.require_var("SessionTime")?;
                let vrpm = s.require_var("RPM")?;
                println!("variables\n\t{:?}\n\t{:?}\n\t{:?}", vss, vst, vrpm);
                println!("State  SessionTime   RPM");
                s.for_each_update(Duration::from_millis(20), |sess| {
                    let st: flags::SessionState = sess.value(&vss)?;
                    let tm: f64 = sess.value(&vst)?;
                    let rpm: f32 = sess.value(&vrpm)?;
                    println!("{:?} {:<14.3}{:.1}", st, tm, rpm);
                    Ok(())
                })?;
            }
        }
    }
}
