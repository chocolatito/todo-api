# RESTful JSON API With Rails 6 - Ver. 3

Example based on the tutorial:
> [___Build a RESTful JSON API With Rails 5 - Part Three___](https://www.digitalocean.com/community/tutorials/build-a-restful-json-api-with-rails-5-part-three)

Continuation of branch
> [***`parte_1`***](https://github.com/chocolatito/todo-api/tree/parte_1)


#### Using
  - `Ruby 2.5.5`
  - `Rails 6.1.4.1`

#### Sumary
+ [Requirements](#requirements)
    - [Data](#data)
    - [API Endpoints](#api-endpoints)
+ [Project Setup](#project-setup)
    - [Dependencies](#dependencies)
    - [Prepare Test Environment](#prepare-test-environment)
+ [Versioning](#versioning)
    - [ApiVersion Class](#apiversion-class)
    - [Content Negotiation](#content-negotiation)
    - [Change Routing](#change-routing)
    - [Module Directory](#module-directory)
    - [Test Endpoints](#test-endpoints)
+ [Serializers](#serializers)
+ [Paginate](#paginate)


---
## Requirements

### Data
- **Todo** : *(title:string, created_by:string)*
- **Item** : *(name:string, done:boolean)*
- **User** : *(name:string, email:string, password_digest:string)*

A **Todo**, has zero or many **Item** records

An **Item**, has only one **Item**

An **User**, has zero or many **Todo** records

A **Todo**, has one **User** records

### API Endpoints

Does not require
- __Log in__
- __Authorization through Json Web Token__

|**Verb**|**URI_Pattern**|**Controller#Actio**|
|------------|------------|------------|
|`POST` | */signup* | __users#create__ |
|`POST` | */auth/login* | __authentication#authenticate__ |

Require __Log in__ and __Authorization through Json Web Token__

|**Verb**|**URI_Pattern**|**Controller#Actio**|
|------------|------------|------------|
|`GET` |_/todos_  | __todos#index__ |
|`POST` |_/todos_ | __todos#create__|
|`GET` |_/todos/:id_ | __todos#show__|
|`PUT` |_/todos/:id_ | __todos#update__ | 
|`DELETE` |_/todos/:id_ | __todos#destroy__ |
|`GET` |*/todos/:todo_id/items* | __items#index__ |
|`POST` | */todos/:todo_id/items* | __items#create__ |
|`GET` |*/todos/:todo_id/items/:id* | __items#show__ |
|`PUT` |*/todos/:todo_id/items/:id* |  __items#update__ |
|`DELETE` |*/todos/:todo_id/items/:id* |  __items#destroy__ |


---
## Project Setup

>___./Gemfile___
```ruby
# [...]
gem 'active_model_serializers', '~> 0.10.0'
# [...]
# Implement token-based authentication.
  gem 'will_paginate', '~> 3.1.0'
# [...]
```

Install the gem.
```sh
bundle install
```

---
## Versioning
In order to version a Rails API, we need to do two things:
- Add a route constraint: This will select a version based on the request headers
- Namespace the controllers: Have different controller namespaces to handle different versions.

> Rails routing supports [__advanced constraints__](http://guides.rubyonrails.org/routing.html#advanced-constraints). Provided an object that responds to matches?, you can control which controller handles a specific route.

### ApiVersion Class
The class will live in `app/lib` since it’s non-domain-specific.

create the class file
```sh
touch app/lib/api_version.rb
```
Implement `ApiVersion`
>***./app/lib/api_version.rb***
```ruby
class ApiVersion
  attr_reader :version, :default

  def initialize(version, default = false)
    @version = version
    @default = default
  end

  # check whether version is specified or is default
  def matches?(request)
    check_headers(request.headers) || default
  end

  private

  def check_headers(headers)
    # check version from Accept headers; expect custom media type `todos`
    accept = headers[:accept]
    accept && accept.include?("application/vnd.todos.#{version}+json")
  end
end
```

ApiVersion class implements server-driven [_content negotiation_](https://en.wikipedia.org/wiki/Content_negotiation) where the client (user agent) informs the server what media types it understands by providing an Accept HTTP header.

`application/vnd.todos.{version_number}+json` is a custom _vendor media type_, that give clients the ability to choose which API version they require.

#### Content Negotiation
REST is closely tied to the HTTP specification. HTTP defines mechanisms that make it possible to serve different versions (representations) of a resource at the same URI. This is called [_content negotiation_](https://en.wikipedia.org/wiki/Content_negotiation).

According to the Media Type Specification, you can define your own media types using the vendor tree i.e.
> `application/vnd.example.resource+json`.

> The [**vendor tree**](https://en.wikipedia.org/wiki/Media_type#Vendor_tree) is used for media types associated with publicly available products. It uses the “vnd” facet.

### Change Routing
Move the existing todos and todo-items resources into a v1 namespace
>***./config/routes***
```ruby
Rails.application.routes.draw do
  # namespace the controllers without affecting the URI
  scope module: :v1, constraints: ApiVersion.new('v1', true) do
    resources :todos do
      resources :items
    end
  end

  post 'auth/login', to: 'authentication#authenticate'
  post 'signup', to: 'users#create'
end
```

In cases where the version is not provided, the API will default to v1.

### Module Directory
Create a module directory in the controllers folder.
```sh
mkdir app/controllers/v1
```
Move the files into the module folder.
```sh
mv app/controllers/{todos_controller.rb,items_controller.rb} app/controllers/v1
```
 
Define the controllers in the v1 namespace.
> ***./app/controllers/v1/todos_controller.rb***
```ruby
module V1
class TodosController < ApplicationController
# [...]
end
end
```

>***./app/controllers/v1/items_controller.rb***
```ruby
module V1
class ItemsController < ApplicationController
# [...]
end
end
```

### Test Endpoints
For testing purposes, let’s define v2.

Generate a v2 todos controller
```sh
rails g controller v2/todos
```

Define the namespace in the routes.
>***./config/routes.rb***
```ruby
Rails.application.routes.draw do
  # module the controllers without affecting the URI
  scope module: :v2, constraints: ApiVersion.new('v2') do
    resources :todos, only: :index
  end
  scope module: :v1, constraints: ApiVersion.new('v1', true) do
    # [...]
  end
  # [...]
end
```
define an index controller with a dummy response.
>***./app/controllers/v2/todos_controller.rb***
```ruby
class V2::TodosController < ApplicationController
  def index
    json_response({ message: 'Hello there'})
  end
end
```
The namespace syntax `class V2::TodosController < ApplicationController` is shorthand in Ruby to define a class within a namespace.

---
---


---
## Serializers
Serializers allow for custom representations of JSON responses. [Active model serializers](https://github.com/rails-api/active_model_serializers) (gen `active_model_serializers` adding in [*Dependencies*](#dependencies)) make it easy to define which model attributes and relationships need to be serialized.

Generate a serializer from the `Todo` model:
```sh
rails g serializer todo
```
This creates a new directory *app/serializers* and adds a new file *todo_serializer.rb*. 

Define the todo serializer with the data that to contain.
>***./app/serializers/todo_serializer.rb***
```ruby
class TodoSerializer < ActiveModel::Serializer
  # attributes to be serialized
  attributes :id, :title, :created_by, :created_at, :updated_at
  # model association
  has_many :items
end
```

## Paginate
Modify the todos controller index action to paginate its response.
>***./app/controllers/v1/todos_controller.rb***
```ruby
module V1
  class TodosController < ApplicationController
  # [...]
  # GET /todos
  def index
    # get paginated current user todos
    @todos = current_user.todos.paginate(page: params[:page], per_page: 20)
    json_response(@todos)
  end
  # [...]
end
```
The index action checks for the page number in the request params. If provided, it’ll return the page data with each page having twenty records each.

The page number is part of the query string.
If request the second page and you have no more than 20 records in the database then an empty array will be returned.

In db/seeds.rb let’s define seed data.
>***./db/seeds.rb***
```ruby
# seed 50 records
50.times do
  todo = Todo.create(title: Faker::Lorem.word, created_by: User.first.id)
  todo.items.create(name: Faker::Lorem.word, done: false)
end
```
Seed the database by running:
```sh
rake db:seed
```

---