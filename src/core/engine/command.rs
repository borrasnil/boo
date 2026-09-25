use super::{OS, Obfuscate};

pub struct Pipeline {
    os: OS,
    modules: Vec<Box<dyn Obfuscate>>,
}

impl Pipeline {
    pub fn new(os: OS) -> Self {
        Pipeline {
            os,
            modules: vec![],
        }
    }

    pub fn add(mut self, module: impl Obfuscate + 'static) -> Self {
        self.modules.push(Box::new(module));
        self
    }

    pub fn run(&self, command: &str) -> String {
        let mut order: Vec<usize> = (0..self.modules.len()).collect();
        order.sort_by_key(|&i| self.modules[i].module_type().weight());
        order.iter().fold(command.to_string(), |acc, &i| {
            self.modules[i].apply(&acc, self.os)
        })
    }
}
