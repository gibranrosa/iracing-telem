use std::{thread, time::Duration};

use iracing_telem::flags::{BroadcastMsg, FFBCommand};

fn main() -> Result<(), iracing_telem::safe::SafeError> {
    let mut c = iracing_telem::safe::Client::new();
    println!("Start iRacing");
    match c.wait_for_session(Duration::new(600, 0))? {
        None => {
            println!("remember to start iRacing");
        }
        Some(s) => {
            s.broadcast_msg(BroadcastMsg::FFBCommand(FFBCommand::MaxForce(22.0)))?;
            thread::sleep(Duration::new(5, 0));
            s.broadcast_msg(BroadcastMsg::FFBCommand(FFBCommand::MaxForce(-1.0)))?;
        }
    }
    Ok(())
}
