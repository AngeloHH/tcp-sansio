mod device;
mod stack;

use pyo3::prelude::*;
use pyo3::{create_exception, exceptions};
use stack::Engine;

create_exception!(_native, AddressInUseError, exceptions::PyOSError);
create_exception!(_native, PacketError, exceptions::PyValueError);
create_exception!(_native, TCPStateError, exceptions::PyConnectionError);

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Engine>()?;
    module.add(
        "AddressInUseError",
        module.py().get_type::<AddressInUseError>(),
    )?;
    module.add("PacketError", module.py().get_type::<PacketError>())?;
    module.add("TCPStateError", module.py().get_type::<TCPStateError>())?;
    Ok(())
}
