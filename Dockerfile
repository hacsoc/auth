FROM jimmycuadra/rust
MAINTAINER Matthew Bentley "bentley@case.edu"

ENV USER "Matthew Bentley"

RUN mkdir /auth
ADD . /auth
WORKDIR /auth

RUN cargo build --release

CMD ["/auth/target/release/auth"]
